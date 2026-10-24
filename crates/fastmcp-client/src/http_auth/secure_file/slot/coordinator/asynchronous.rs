//! Caller-owned asynchronous access to the coordinated credential slot.
//!
//! File and anchor operations run in the supplied runtime's blocking pool.
//! Submission transfers the entire slot, including its file lock, to one job;
//! there is no second usable owner while a transaction is outstanding. A
//! cancelled wait retains its completion mailbox and can be resumed. Cancelling
//! the job is explicit and never means that a transaction did not commit.
//!
//! A shared `CredentialIoLane` bounds open owners, jobs and framework buffer
//! reservations, including unread completions. Cancellation cannot release a
//! running worker's reservation. The caller supplies the admission domain;
//! opening another store does not silently create another budget.
//!
//! This is still storage for caller-protected blobs. Encryption, an independent
//! durable anchor, provider authentication, and restore-epoch custody remain
//! the existing coordinator's deployment requirements. No runtime, thread pool,
//! plaintext persistence, detached cleanup worker, or provider fallback is added.

use std::fmt;
use std::fs::File;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::runtime::{BlockingTaskHandle, TaskHandle};
use asupersync::sync::Notify;
use fastmcp_core::partition::{CredentialStoreKey, PartitionAuthorization};
use fastmcp_core::runtime::ProcessBoundToken;

use super::super::super::{AtomicFileError, MAX_ATOMIC_FILE_BYTES, SecureAtomicFile};
use super::super::{
    CredentialSlotError, HEADER_BYTES, SlotCommit, SlotRecoveryOutcome, SlotRevision,
};
use super::{CoordinatedCredentialSlot, CoordinatedSlotError, CredentialCommitAnchor};

mod admission;
pub(crate) mod composed;
use admission::{CONTROL_BYTES, JobLease, SlotLease, operation_bytes};
pub use admission::{
    CredentialDrainError, CredentialIoLane, CredentialIoLimits, CredentialIoSnapshot,
};

/// Scheduling/wait failures, distinct from the transaction's own disposition.
/// In particular WaitCancelled/WaitTimedOut say nothing about commit status.
/// No error retains a path, credential, or provider panic payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialIoError {
    ProcessChanged,
    InvalidLimits,
    InvalidSlotConfiguration,
    CapacityExceeded,
    LaneClosed,
    AdmissionUnavailable,
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
            Self::InvalidLimits => "credential I/O limits are invalid",
            Self::InvalidSlotConfiguration => {
                "credential I/O slot configuration exceeds its bounds"
            }
            Self::CapacityExceeded => "credential I/O admission capacity exhausted",
            Self::LaneClosed => "credential I/O lane is shutting down",
            Self::AdmissionUnavailable => "credential I/O admission state unavailable",
            Self::CapabilityUnavailable => {
                "credential I/O requires caller-owned spawn, I/O and time capabilities"
            }
            Self::BlockingPoolUnavailable => {
                "credential I/O requires an installed caller-owned blocking pool"
            }
            Self::SubmissionCancelled => "credential I/O submission cancelled",
            Self::SubmissionTimedOut => "credential I/O submission deadline exceeded",
            Self::RuntimeUnavailable => "credential I/O could not enter the caller's runtime",
            Self::WaitCancelled => {
                "credential I/O wait cancelled; transaction disposition is not implied"
            }
            Self::WaitTimedOut => {
                "credential I/O wait timed out; transaction disposition is not implied"
            }
            Self::WorkerStopped => {
                "credential I/O worker stopped without a completion; reopen and reconcile"
            }
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
/// Capacity remains charged until BOTH the worker and this owner release it.
#[must_use = "retain the operation to observe its transaction disposition"]
pub struct CredentialSlotTask<T> {
    process: Arc<ProcessBoundToken>,
    worker: Option<TaskHandle<()>>,
    // Drop a retained result before dropping its byte reservation.
    receiver: oneshot::Receiver<Result<T, CredentialIoError>>,
    lease: Option<Arc<JobLease>>,
    received: bool,
}

impl<T> CredentialSlotTask<T> {
    /// Waits without resubmitting. A completion, including a terminal worker
    /// failure, is delivered once. Caller cancellation or deadline ends only
    /// this wait and consumes nothing. A later wait may use a fresh live Cx.
    /// The caller's timer is required when it sets a deadline. A returned value
    /// transfers to application custody and no longer consumes this lane's
    /// buffer budget; the live slot owner continues consuming a slot admission.
    pub async fn wait(&mut self, cx: &Cx) -> Result<T, CredentialIoError> {
        self.process
            .verify()
            .map_err(|_| CredentialIoError::ProcessChanged)?;
        if self.received {
            return Err(CredentialIoError::AlreadyReceived);
        }
        cx.checkpoint()
            .map_err(|_| CredentialIoError::WaitCancelled)?;
        let received = if let Some(deadline) = cx.budget().deadline {
            if !cx.capabilities().time || cx.timer_driver().is_none() {
                return Err(CredentialIoError::CapabilityUnavailable);
            }
            if cx.now() >= deadline {
                return Err(CredentialIoError::WaitTimedOut);
            }
            asupersync::time::timeout_at(deadline, self.receiver.recv(cx))
                .await
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
                self.lease = None;
                result
            }
            Err(oneshot::RecvError::Cancelled) => Err(CredentialIoError::WaitCancelled),
            Err(oneshot::RecvError::Closed) => {
                self.received = true;
                if let Some(worker) = self.worker.take() {
                    worker.abort();
                }
                self.lease = None;
                Err(CredentialIoError::WorkerStopped)
            }
            Err(oneshot::RecvError::PolledAfterCompletion) => {
                self.received = true;
                if let Some(worker) = self.worker.take() {
                    worker.abort();
                }
                self.lease = None;
                Err(CredentialIoError::AlreadyReceived)
            }
        }
    }

    /// Requests cancellation of this worker only. Keep waiting to discover its
    /// actual storage outcome. Cancellation cannot reverse rename or anchor CAS.
    pub fn request_cancel(&self) -> Result<(), CredentialIoError> {
        self.process
            .verify()
            .map_err(|_| CredentialIoError::ProcessChanged)?;
        if let Some(worker) = &self.worker {
            worker.abort();
        }
        Ok(())
    }
}

impl<T> Drop for CredentialSlotTask<T> {
    fn drop(&mut self) {
        if self.process.verify().is_ok() {
            if let Some(worker) = &self.worker {
                worker.abort();
            }
        }
    }
}
impl<T> fmt::Debug for CredentialSlotTask<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialSlotTask")
            .field("received", &self.received)
            .finish_non_exhaustive()
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
    pub fn into_parts(
        self,
    ) -> (
        AsyncCoordinatedCredentialSlot<A>,
        Result<T, CoordinatedSlotError>,
    ) {
        (self.owner, self.outcome)
    }
}

/// Result of opening/recovering through the caller-owned blocking lane.
pub type CredentialSlotOpen<A> = Result<
    (
        AsyncCoordinatedCredentialSlot<A>,
        Option<SlotRecoveryOutcome>,
    ),
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
    lane: CredentialIoLane,
    maximum_file_bytes: usize,
    // Release the provider and file lock before returning slot capacity.
    slot: CoordinatedCredentialSlot<A>,
    slot_lease: SlotLease,
}

impl<A: CredentialCommitAnchor + 'static> AsyncCoordinatedCredentialSlot<A> {
    /// Opens and, when necessary, recovers both file and anchor in the worker.
    /// The directory handle and shared admission lane are supplied by the host;
    /// no ambient path is opened and no per-open capacity domain is created.
    /// The returned task, not this method, owns the opening/recovery outcome.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        cx: &Cx,
        lane: &CredentialIoLane,
        directory: File,
        leaf: String,
        maximum_bytes: usize,
        key: CredentialStoreKey,
        authorization: PartitionAuthorization,
        namespace: String,
        anchor: A,
    ) -> Result<CredentialSlotTask<CredentialSlotOpen<A>>, CredentialIoError> {
        check_submission(cx, &lane.process())?;
        if !(HEADER_BYTES..=MAX_ATOMIC_FILE_BYTES).contains(&maximum_bytes)
            || leaf.is_empty()
            || leaf.len() > 96
            || namespace.is_empty()
            || namespace.len() > 128
        {
            return Err(CredentialIoError::InvalidSlotConfiguration);
        }
        let slot_lease = lane.reserve_slot()?;
        let process = lane.process();
        let owner_lane = lane.clone();
        // Do not queue unbounded spare capacity supplied in an otherwise short
        // String. The caller's original allocations are outside lane custody.
        let leaf = leaf.into_boxed_str();
        let namespace = namespace.into_boxed_str();
        submit(
            cx,
            lane,
            operation_bytes(maximum_bytes)?,
            move |worker_cx| {
                let file = SecureAtomicFile::open(worker_cx, directory, &leaf, maximum_bytes)
                    .map_err(|error| {
                        CoordinatedSlotError::Slot(CredentialSlotError::Storage(error))
                    })?;
                let (slot, recovery) = CoordinatedCredentialSlot::open(
                    worker_cx,
                    file,
                    &key,
                    &authorization,
                    &namespace,
                    anchor,
                )?;
                Ok((
                    Self {
                        process,
                        lane: owner_lane,
                        maximum_file_bytes: maximum_bytes,
                        slot,
                        slot_lease,
                    },
                    recovery,
                ))
            },
        )
    }

    pub fn revision(&self) -> Option<SlotRevision> {
        self.slot.revision()
    }
    pub fn requires_recovery(&self) -> bool {
        self.slot.requires_recovery()
    }
    pub fn maximum_payload_bytes(&self) -> usize {
        self.slot.maximum_payload_bytes()
    }

    /// Authenticated ciphertext lookup, preserving absent versus tombstoned state
    /// through the returned owner's revision. It does not decrypt a credential.
    pub fn load(
        self,
        cx: &Cx,
        authorization: PartitionAuthorization,
    ) -> Result<CredentialSlotTask<CredentialSlotCompletion<A, Option<Vec<u8>>>>, CredentialIoError>
    {
        self.operate(cx, move |slot, cx| slot.load(cx, &authorization))
    }

    /// Commits protected bytes through the existing intent/file/anchor sequence.
    /// Success is never synthesized from a runtime join or an observed filename.
    pub fn replace(
        self,
        cx: &Cx,
        authorization: PartitionAuthorization,
        expected: Option<SlotRevision>,
        protected_payload: Vec<u8>,
    ) -> Result<CredentialSlotTask<CredentialSlotCompletion<A, SlotRevision>>, CredentialIoError>
    {
        if protected_payload.len() > self.maximum_payload_bytes() {
            drop(protected_payload);
            check_submission(cx, &self.process)?;
            let lease = self.lane.reserve_job(CONTROL_BYTES)?;
            return Ok(ready(
                Arc::clone(&self.process),
                lease,
                CredentialSlotCompletion {
                    owner: self,
                    outcome: Err(CoordinatedSlotError::Slot(CredentialSlotError::Storage(
                        AtomicFileError::TooLarge,
                    ))),
                },
            ));
        }
        // Length, not attacker-supplied spare Vec capacity, defines queued input.
        let protected_payload = protected_payload.into_boxed_slice();
        self.operate(cx, move |slot, cx| {
            slot.replace(cx, &authorization, expected, &protected_payload)
        })
    }

    /// Releases the old protected payload only after the coordinated tombstone
    /// commit. Retaining the pending task, rather than retrying take, is how a
    /// caller survives interruption of its wait without duplicating the handoff.
    pub fn take(
        self,
        cx: &Cx,
        authorization: PartitionAuthorization,
        expected: SlotRevision,
    ) -> Result<CredentialSlotTask<CredentialSlotCompletion<A, SlotCommit>>, CredentialIoError>
    {
        self.operate(cx, move |slot, cx| slot.take(cx, &authorization, expected))
    }

    /// Persistent logout/invalidation; no old credential payload is returned.
    pub fn invalidate(
        self,
        cx: &Cx,
        authorization: PartitionAuthorization,
    ) -> Result<CredentialSlotTask<CredentialSlotCompletion<A, SlotRevision>>, CredentialIoError>
    {
        self.operate(cx, move |slot, cx| slot.invalidate(cx, &authorization))
    }

    /// Drops the file lock and provider on the owned blocking lane. This is
    /// local closure only: it neither invalidates storage nor revokes a token.
    /// Close has dedicated bounded capacity, even when data jobs are saturated.
    pub fn close(self, cx: &Cx) -> Result<CredentialSlotTask<()>, CredentialIoError> {
        check_submission(cx, &self.process)?;
        let lease = self.slot_lease.reserve_close()?;
        spawn(cx, Arc::clone(&self.process), lease, move |_| drop(self))
    }

    fn operate<T, F>(
        mut self,
        cx: &Cx,
        operation: F,
    ) -> Result<CredentialSlotTask<CredentialSlotCompletion<A, T>>, CredentialIoError>
    where
        T: Send + 'static,
        F: FnOnce(&mut CoordinatedCredentialSlot<A>, &Cx) -> Result<T, CoordinatedSlotError>
            + Send
            + 'static,
    {
        let lane = self.lane.clone();
        submit(
            cx,
            &lane,
            operation_bytes(self.maximum_file_bytes)?,
            move |worker_cx| {
                let outcome = operation(&mut self.slot, worker_cx);
                CredentialSlotCompletion {
                    owner: self,
                    outcome,
                }
            },
        )
    }
}
impl<A> fmt::Debug for AsyncCoordinatedCredentialSlot<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncCoordinatedCredentialSlot")
            .finish_non_exhaustive()
    }
}

fn check_submission(cx: &Cx, process: &ProcessBoundToken) -> Result<(), CredentialIoError> {
    process
        .verify()
        .map_err(|_| CredentialIoError::ProcessChanged)?;
    cx.checkpoint()
        .map_err(|_| CredentialIoError::SubmissionCancelled)?;
    let capabilities = cx.capabilities();
    if !capabilities.spawn || !capabilities.io || !capabilities.time {
        return Err(CredentialIoError::CapabilityUnavailable);
    }
    // Require the caller's pool here; spawn below uses its raw non-fallback
    // submission API even when a present pool rejects work during shutdown.
    if cx.blocking_pool_handle().is_none() {
        return Err(CredentialIoError::BlockingPoolUnavailable);
    }
    if cx
        .budget()
        .deadline
        .is_some_and(|deadline| cx.now() >= deadline)
    {
        return Err(CredentialIoError::SubmissionTimedOut);
    }
    Ok(())
}

fn ready<T>(
    process: Arc<ProcessBoundToken>,
    lease: Arc<JobLease>,
    value: T,
) -> CredentialSlotTask<T> {
    let (sender, receiver) = oneshot::channel();
    let _ = sender.send_blocking(Ok(value));
    CredentialSlotTask {
        process,
        worker: None,
        receiver,
        lease: Some(lease),
        received: false,
    }
}

fn submit<T, F>(
    cx: &Cx,
    lane: &CredentialIoLane,
    bytes: usize,
    work: F,
) -> Result<CredentialSlotTask<T>, CredentialIoError>
where
    T: Send + 'static,
    F: FnOnce(&Cx) -> T + Send + 'static,
{
    let process = lane.process();
    check_submission(cx, &process)?;
    let lease = lane.reserve_job(bytes)?;
    spawn(cx, process, lease, work)
}

fn spawn<T, F>(
    cx: &Cx,
    process: Arc<ProcessBoundToken>,
    lease: Arc<JobLease>,
    work: F,
) -> Result<CredentialSlotTask<T>, CredentialIoError>
where
    T: Send + 'static,
    F: FnOnce(&Cx) -> T + Send + 'static,
{
    let pool = cx
        .blocking_pool_handle()
        .ok_or(CredentialIoError::BlockingPoolUnavailable)?;
    let worker_process = Arc::clone(&process);
    let worker_lease = Arc::clone(&lease);
    let (sender, receiver) = oneshot::channel();
    let worker = cx
        .spawn(move |worker_cx| async move {
            let _child_lease = Arc::clone(&worker_lease);
            let completion = Arc::new(CredentialPoolCompletion::default());
            let context = worker_cx.clone();
            let job = CredentialPoolWork {
                work: Some(move || {
                    let result = if worker_process.verify().is_err() {
                        Err(CredentialIoError::ProcessChanged)
                    } else {
                        // Preserve the transaction disposition outside the
                        // runtime join's cancellation result and redact panics.
                        catch_unwind(AssertUnwindSafe(|| work(&context)))
                            .map_err(|_| CredentialIoError::WorkerPanicked)
                    };
                    // Publication is not another credential effect. A committed
                    // result remains deliverable after worker cancellation.
                    let _ = sender.send_blocking(result);
                }),
                _lease: worker_lease,
                _completion: CredentialPoolCompletionGuard(Arc::clone(&completion)),
            };
            // Cx::spawn_blocking can execute inline after pool rejection. Raw
            // pool submission instead drops rejected work without invoking it.
            let pool_task = CredentialPoolTask(pool.spawn(move || job.run()));
            let (_cancel_guard, mut cancellation) = oneshot::channel::<()>();
            let mut cancelled = std::pin::pin!(cancellation.recv(&worker_cx));
            let mut finished = std::pin::pin!(
                completion
                    .changed
                    .wait_until(|| completion.done.load(Ordering::Acquire))
            );
            let mut cancellation_forwarded = false;
            poll_fn(|task| {
                if !cancellation_forwarded && cancelled.as_mut().poll(task).is_ready() {
                    pool_task.0.cancel();
                    cancellation_forwarded = true;
                }
                // Retain region ownership until the actual closure and captured
                // slot are disposed, including a non-preemptible running call.
                // This wake is cancellation-independent and cannot busy-spin on
                // an already-cancelled runtime timer or receiver.
                finished.as_mut().poll(task)
            })
            .await;
        })
        .map_err(|_| CredentialIoError::RuntimeUnavailable)?;
    Ok(CredentialSlotTask {
        process,
        worker: Some(worker),
        receiver,
        lease: Some(lease),
        received: false,
    })
}

#[derive(Default)]
struct CredentialPoolCompletion {
    done: AtomicBool,
    changed: Notify,
}

struct CredentialPoolCompletionGuard(Arc<CredentialPoolCompletion>);

impl Drop for CredentialPoolCompletionGuard {
    fn drop(&mut self) {
        self.0.done.store(true, Ordering::Release);
        let _ = catch_unwind(AssertUnwindSafe(|| self.0.changed.notify_waiters()));
    }
}

// Fields drop in declaration order even when a queued job is never invoked.
// Signal completion only after disposing its captured slot/result sender and
// the worker's reservation; the supervisor then releases its remaining charge.
struct CredentialPoolWork<F> {
    work: Option<F>,
    _lease: Arc<JobLease>,
    _completion: CredentialPoolCompletionGuard,
}

impl<F: FnOnce()> CredentialPoolWork<F> {
    fn run(mut self) {
        self.work.take().expect("credential pool work runs once")();
    }
}

struct CredentialPoolTask(BlockingTaskHandle);

impl Drop for CredentialPoolTask {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
mod tests;
