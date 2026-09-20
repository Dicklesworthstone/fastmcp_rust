//! Caller-owned capacity for asynchronous credential storage.
//!
//! Share one lane across the stores in an application admission domain. Cloning
//! a lane shares its counters; it does not create another budget. Applications
//! creating independent lanes are responsible for their aggregate process cap.
//! No thread pool, runtime, background waiter or global registry is introduced.

use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::time::Sleep;

use fastmcp_core::runtime::{ProcessBoundToken, ProcessGenerationGuard};

use super::CredentialIoError;

const MAX_SLOTS: usize = 1_024;
const MAX_OPERATIONS: usize = 256;
const MAX_RESERVED_BYTES: usize = 256 * 1024 * 1024;
const MAX_DRAIN_WAIT: Duration = Duration::from_secs(300);
pub(super) const CONTROL_BYTES: usize = 16 * 1024;

/// Bounds for retained file owners, ordinary jobs and their framework buffers.
/// Jobs include queued/running work AND completions not yet received or dropped.
/// Provider-internal memory and application-owned returned values are outside
/// the byte charge; the provider must separately bound its own memory and I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialIoLimits {
    maximum_slots: usize,
    maximum_operations: usize,
    reserved_bytes: usize,
}

impl Default for CredentialIoLimits {
    fn default() -> Self {
        Self { maximum_slots: 128, maximum_operations: 32, reserved_bytes: 16 * 1024 * 1024 }
    }
}

impl CredentialIoLimits {
    pub fn new(slots: usize, operations: usize, bytes: usize) -> Result<Self, CredentialIoError> {
        if slots == 0 || slots > MAX_SLOTS || operations == 0 || operations > MAX_OPERATIONS
            || !(CONTROL_BYTES..=MAX_RESERVED_BYTES).contains(&bytes)
        {
            return Err(CredentialIoError::InvalidLimits);
        }
        Ok(Self { maximum_slots: slots, maximum_operations: operations, reserved_bytes: bytes })
    }

    pub fn maximum_slots(self) -> usize { self.maximum_slots }
    pub fn maximum_operations(self) -> usize { self.maximum_operations }
    pub fn maximum_reserved_bytes(self) -> usize { self.reserved_bytes }
}

/// One coherent, non-secret view of the lane. Slot owners include those held
/// by a worker or unread completion, not merely handles returned to application
/// code. Close jobs have their own bounded lane so saturation cannot prevent
/// releasing an already-admitted owner.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CredentialIoSnapshot {
    pub slots: usize,
    pub operations: usize,
    pub closes: usize,
    pub reserved_bytes: usize,
}

/// Drain observation never cancels an in-flight transaction, discards an
/// unread result, or releases another owner's file lock. A timeout/cancellation
/// ends this observer only; the lane remains shut to ordinary admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialDrainError {
    Admission(CredentialIoError),
    ShutdownRequired,
    ObserverBusy,
    ObserverSequenceExhausted,
    InvalidTimeout,
    TimerUnavailable,
    Cancelled,
    TimedOut,
}

impl fmt::Display for CredentialDrainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => error.fmt(f),
            Self::ShutdownRequired => f.write_str("credential I/O shutdown has not begun"),
            Self::ObserverBusy => f.write_str("credential I/O already has a drain observer"),
            Self::ObserverSequenceExhausted => f.write_str("credential I/O drain observer sequence exhausted"),
            Self::InvalidTimeout => f.write_str("credential I/O drain timeout must be positive and at most five minutes"),
            Self::TimerUnavailable => f.write_str("credential I/O drain requires the caller's timer"),
            Self::Cancelled => f.write_str("credential I/O drain observation cancelled; shutdown remains active"),
            Self::TimedOut => f.write_str("credential I/O drain observation timed out; shutdown remains active"),
        }
    }
}
impl std::error::Error for CredentialDrainError {}
impl From<CredentialIoError> for CredentialDrainError {
    fn from(error: CredentialIoError) -> Self { Self::Admission(error) }
}

struct DrainWaiter { id: u64, sender: oneshot::Sender<()> }

#[derive(Default)]
struct LaneState {
    usage: CredentialIoSnapshot,
    shutting_down: bool,
    next_observer: u64,
    waiter: Option<DrainWaiter>,
}
impl LaneState {
    fn take_drained_waiter(&mut self) -> Option<DrainWaiter> {
        if self.shutting_down && self.usage == CredentialIoSnapshot::default() {
            self.waiter.take()
        } else { None }
    }
}

struct LaneInner {
    process: Arc<ProcessBoundToken>,
    limits: CredentialIoLimits,
    // Only fixed-size counter arithmetic under this mutex. Never call a
    // provider, filesystem, runtime, destructor or user Waker while holding it.
    state: Mutex<LaneState>,
}

/// Shared admission authority installed by the application, before opening
/// stores. A rejected admission does not enter the blocking pool or contact an
/// anchor. There is no unbounded waiter queue and no polling-thread fallback.
#[derive(Clone)]
pub struct CredentialIoLane {
    inner: Arc<LaneInner>,
}

impl CredentialIoLane {
    pub fn new(guard: &ProcessGenerationGuard, limits: CredentialIoLimits) -> Result<Self, CredentialIoError> {
        guard.verify_current().map_err(|_| CredentialIoError::ProcessChanged)?;
        Ok(Self { inner: Arc::new(LaneInner {
            process: Arc::new(guard.token()), limits, state: Mutex::new(LaneState::default()),
        }) })
    }

    pub fn limits(&self) -> CredentialIoLimits { self.inner.limits }

    pub fn snapshot(&self) -> Result<CredentialIoSnapshot, CredentialIoError> {
        self.verify()?;
        self.inner.state.lock().map(|state| state.usage).map_err(|_| CredentialIoError::AdmissionUnavailable)
    }

    /// Irreversibly stops new opens and ordinary operations across every clone.
    /// Existing operations retain their actual transaction semantics. Explicit
    /// close remains admitted through its separate bounded lane. This returns
    /// the outstanding charges at the shutdown boundary, not a cleanup receipt.
    pub fn begin_shutdown(&self) -> Result<CredentialIoSnapshot, CredentialIoError> {
        self.verify()?;
        let (usage, waiter) = {
            let mut state = self.inner.state.lock().map_err(|_| CredentialIoError::AdmissionUnavailable)?;
            state.shutting_down = true;
            (state.usage, state.take_drained_waiter())
        };
        notify(waiter);
        Ok(usage)
    }

    pub fn is_shutting_down(&self) -> Result<bool, CredentialIoError> {
        self.verify()?;
        self.inner.state.lock().map(|state| state.shutting_down).map_err(|_| CredentialIoError::AdmissionUnavailable)
    }

    /// Observes a lane already closed by `begin_shutdown`. Success means every
    /// admitted slot owner, job, close job and unread completion has released
    /// its lane charge. It does NOT join the runtime's entire region, revoke
    /// tokens, or establish independent provider crash durability.
    ///
    /// The application must consume/discard pending results and close/drop
    /// returned slot owners; retaining either intentionally prevents success.
    /// At most one drain observer is registered. Dropping this future, timeout
    /// or cancellation retires that exact registration without reopening the
    /// lane. Another live observer may resume against the same outstanding work.
    pub async fn wait_drained(&self, cx: &Cx, timeout: Duration) -> Result<(), CredentialDrainError> {
        self.verify()?;
        if timeout.is_zero() || timeout > MAX_DRAIN_WAIT { return Err(CredentialDrainError::InvalidTimeout); }
        cx.checkpoint().map_err(|_| CredentialDrainError::Cancelled)?;
        if !cx.capabilities().time || cx.timer_driver().is_none() {
            return Err(CredentialDrainError::TimerUnavailable);
        }
        let requested = cx.now().saturating_add_nanos(timeout.as_nanos() as u64);
        let deadline = cx.budget().deadline.map_or(requested, |parent| parent.min(requested));
        if cx.now() >= deadline { return Err(CredentialDrainError::TimedOut); }
        let Some((_registration, mut receiver)) = self.register_observer()? else { return Ok(()); };
        let mut received = pin!(receiver.recv(cx));
        let mut timer = pin!(Sleep::new(deadline));
        poll_fn(|task| {
            self.verify()?;
            if cx.now() >= deadline { return Poll::Ready(Err(CredentialDrainError::TimedOut)); }
            cx.checkpoint().map_err(|_| CredentialDrainError::Cancelled)?;
            // Public Sleep resolves its driver on poll. Install only the
            // supplied caller Cx, and never hold this guard across suspension.
            let _caller = Cx::set_current(Some(cx.clone()));
            if timer.as_mut().poll(task).is_ready() { return Poll::Ready(Err(CredentialDrainError::TimedOut)); }
            match received.as_mut().poll(task) {
                Poll::Ready(Ok(())) => {
                    cx.checkpoint().map_err(|_| CredentialDrainError::Cancelled)?;
                    if cx.now() >= deadline { return Poll::Ready(Err(CredentialDrainError::TimedOut)); }
                    // Never turn an unexpected channel close into drain success.
                    if self.snapshot()? != CredentialIoSnapshot::default() {
                        return Poll::Ready(Err(CredentialIoError::AdmissionUnavailable.into()));
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(oneshot::RecvError::Cancelled)) => Poll::Ready(Err(CredentialDrainError::Cancelled)),
                Poll::Ready(Err(_)) => Poll::Ready(Err(CredentialIoError::AdmissionUnavailable.into())),
                Poll::Pending => Poll::Pending,
            }
        }).await
    }

    fn register_observer(&self) -> Result<Option<(DrainRegistration, oneshot::Receiver<()>)>, CredentialDrainError> {
        self.verify()?;
        let mut state = self.inner.state.lock().map_err(|_| CredentialIoError::AdmissionUnavailable)?;
        if !state.shutting_down { return Err(CredentialDrainError::ShutdownRequired); }
        if state.usage == CredentialIoSnapshot::default() { return Ok(None); }
        if state.waiter.is_some() { return Err(CredentialDrainError::ObserverBusy); }
        let id = state.next_observer.checked_add(1).ok_or(CredentialDrainError::ObserverSequenceExhausted)?;
        let (sender, receiver) = oneshot::channel();
        state.next_observer = id;
        state.waiter = Some(DrainWaiter { id, sender });
        Ok(Some((DrainRegistration { lane: self.clone(), id }, receiver)))
    }

    pub(super) fn process(&self) -> Arc<ProcessBoundToken> { Arc::clone(&self.inner.process) }

    fn verify(&self) -> Result<(), CredentialIoError> {
        // Check before accessing a possibly inherited locked mutex after fork.
        self.inner.process.verify().map_err(|_| CredentialIoError::ProcessChanged)
    }

    pub(super) fn reserve_slot(&self) -> Result<SlotLease, CredentialIoError> {
        self.verify()?;
        let mut state = self.inner.state.lock().map_err(|_| CredentialIoError::AdmissionUnavailable)?;
        if state.shutting_down { return Err(CredentialIoError::LaneClosed); }
        if state.usage.slots >= self.inner.limits.maximum_slots { return Err(CredentialIoError::CapacityExceeded); }
        state.usage.slots += 1;
        Ok(SlotLease { lane: self.clone() })
    }

    pub(super) fn reserve_job(&self, bytes: usize) -> Result<Arc<JobLease>, CredentialIoError> {
        self.verify()?;
        let mut state = self.inner.state.lock().map_err(|_| CredentialIoError::AdmissionUnavailable)?;
        if state.shutting_down { return Err(CredentialIoError::LaneClosed); }
        let total = state.usage.reserved_bytes.checked_add(bytes).ok_or(CredentialIoError::CapacityExceeded)?;
        if state.usage.operations >= self.inner.limits.maximum_operations || total > self.inner.limits.reserved_bytes {
            return Err(CredentialIoError::CapacityExceeded);
        }
        // Both dimensions commit together. A byte refusal cannot consume a job.
        state.usage.operations += 1;
        state.usage.reserved_bytes = total;
        Ok(Arc::new(JobLease { lane: self.clone(), bytes, closing: false }))
    }
}

struct DrainRegistration { lane: CredentialIoLane, id: u64 }
impl Drop for DrainRegistration {
    fn drop(&mut self) {
        if self.lane.verify().is_err() { return; }
        let waiter = if let Ok(mut state) = self.lane.inner.state.lock() {
            if state.waiter.as_ref().is_some_and(|waiter| waiter.id == self.id) { state.waiter.take() } else { None }
        } else { None };
        // Sender drop can wake a receiver. No Waker runs under the state lock.
        drop(waiter);
    }
}

fn notify(waiter: Option<DrainWaiter>) {
    if let Some(waiter) = waiter { let _ = waiter.sender.send_blocking(()); }
}

impl fmt::Debug for CredentialIoLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialIoLane").field("limits", &self.inner.limits).finish_non_exhaustive()
    }
}

/// Cannot be cloned or constructed outside admission. Every close job consumes
/// an existing slot owner, bounding close work independently of the data queue.
pub(super) struct SlotLease { lane: CredentialIoLane }
impl SlotLease {
    pub(super) fn reserve_close(&self) -> Result<Arc<JobLease>, CredentialIoError> {
        self.lane.verify()?;
        let mut state = self.lane.inner.state.lock().map_err(|_| CredentialIoError::AdmissionUnavailable)?;
        if state.usage.closes >= self.lane.inner.limits.maximum_slots { return Err(CredentialIoError::CapacityExceeded); }
        state.usage.closes += 1;
        Ok(Arc::new(JobLease { lane: self.lane.clone(), bytes: 0, closing: true }))
    }
}
impl Drop for SlotLease {
    fn drop(&mut self) {
        if self.lane.verify().is_err() { return; }
        let waiter = if let Ok(mut state) = self.lane.inner.state.lock() {
            state.usage.slots -= 1;
            state.take_drained_waiter()
        } else { None };
        notify(waiter);
    }
}

/// Shared by the task owner and worker. Dropping a wait/task cannot release
/// capacity while a non-preemptible provider is still executing. Conversely,
/// worker completion cannot release an unread result's retained byte charge.
pub(super) struct JobLease { lane: CredentialIoLane, bytes: usize, closing: bool }
impl Drop for JobLease {
    fn drop(&mut self) {
        if self.lane.verify().is_err() { return; }
        let waiter = if let Ok(mut state) = self.lane.inner.state.lock() {
            if self.closing {
                state.usage.closes -= 1;
            } else {
                state.usage.operations -= 1;
                state.usage.reserved_bytes -= self.bytes;
            }
            state.take_drained_waiter()
        } else { None };
        notify(waiter);
    }
}

/// Conservative charge for the atomic read, decoded record, prepared mutation,
/// replacement input and retained result, plus bounded framing/scratch. The
/// caller has already admitted maximum_file_bytes against the atomic-file cap.
pub(super) fn operation_bytes(maximum_file_bytes: usize) -> Result<usize, CredentialIoError> {
    maximum_file_bytes.checked_mul(8).and_then(|bytes| bytes.checked_add(CONTROL_BYTES))
        .ok_or(CredentialIoError::CapacityExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lane(slots: usize, jobs: usize, bytes: usize) -> CredentialIoLane {
        CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(),
            CredentialIoLimits::new(slots, jobs, bytes).unwrap()).unwrap()
    }

    #[test]
    fn rejects_zero_and_overflowing_limits() {
        for (slots, jobs, bytes) in [(0, 1, CONTROL_BYTES), (1, 0, CONTROL_BYTES), (1, 1, 0),
            (MAX_SLOTS + 1, 1, CONTROL_BYTES), (1, MAX_OPERATIONS + 1, CONTROL_BYTES),
            (1, 1, MAX_RESERVED_BYTES + 1), (usize::MAX, usize::MAX, usize::MAX)]
        { assert_eq!(CredentialIoLimits::new(slots, jobs, bytes).err(), Some(CredentialIoError::InvalidLimits)); }
        assert_eq!(operation_bytes(usize::MAX).err(), Some(CredentialIoError::CapacityExceeded));
    }

    #[test]
    fn cloned_lanes_share_slot_and_job_limits_and_recover_after_release() {
        let lane = lane(1, 1, CONTROL_BYTES);
        let clone = lane.clone();
        let slot = lane.reserve_slot().unwrap();
        assert!(matches!(clone.reserve_slot(), Err(CredentialIoError::CapacityExceeded)));
        let job = clone.reserve_job(CONTROL_BYTES).unwrap();
        assert!(matches!(lane.reserve_job(0), Err(CredentialIoError::CapacityExceeded)));
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot { slots: 1, operations: 1, closes: 0, reserved_bytes: CONTROL_BYTES });
        drop(slot);
        drop(job);
        assert_eq!(clone.snapshot().unwrap(), CredentialIoSnapshot::default());
        drop(clone.reserve_slot().unwrap());
        drop(lane.reserve_job(CONTROL_BYTES).unwrap());
    }

    #[test]
    fn byte_refusal_does_not_leak_an_operation_or_disturb_existing_charge() {
        let lane = lane(2, 2, CONTROL_BYTES);
        let job = lane.reserve_job(CONTROL_BYTES - 1).unwrap();
        let before = lane.snapshot().unwrap();
        assert!(matches!(lane.reserve_job(2), Err(CredentialIoError::CapacityExceeded)));
        assert_eq!(lane.snapshot().unwrap(), before);
        let last = lane.reserve_job(1).unwrap();
        assert_eq!(lane.snapshot().unwrap().reserved_bytes, CONTROL_BYTES);
        drop(last);
        drop(job);
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
    }

    #[test]
    fn worker_and_mailbox_must_both_release_before_capacity_returns() {
        let lane = lane(1, 1, CONTROL_BYTES);
        let mailbox = lane.reserve_job(CONTROL_BYTES).unwrap();
        let worker = Arc::clone(&mailbox);
        drop(mailbox);
        assert!(matches!(lane.reserve_job(1), Err(CredentialIoError::CapacityExceeded)));
        drop(worker);
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
    }

    #[test]
    fn close_capacity_is_available_when_data_capacity_is_exhausted() {
        let lane = lane(1, 1, CONTROL_BYTES);
        let slot = lane.reserve_slot().unwrap();
        let job = lane.reserve_job(CONTROL_BYTES).unwrap();
        let close = slot.reserve_close().unwrap();
        assert_eq!(lane.snapshot().unwrap().closes, 1);
        drop(slot);
        drop(job);
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot { closes: 1, ..Default::default() });
        drop(close);
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
    }

    #[test]
    fn concurrent_reservations_never_exceed_the_last_slot_or_job() {
        let lane = lane(1, 1, CONTROL_BYTES);
        let start = Arc::new(std::sync::Barrier::new(9));
        let finish = Arc::new(std::sync::Barrier::new(9));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let lane = lane.clone();
            let start = start.clone();
            let finish = finish.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                let job = lane.reserve_job(CONTROL_BYTES);
                finish.wait();
                job.is_ok()
            }));
        }
        start.wait();
        finish.wait();
        let successes = workers.into_iter().map(|worker| usize::from(worker.join().unwrap())).sum::<usize>();
        assert_eq!(successes, 1);
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
    }

    fn runtime() -> asupersync::runtime::Runtime {
        asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap()
    }

    #[test]
    fn shutdown_is_one_way_and_preserves_cleanup_admission() {
        let lane = lane(1, 1, CONTROL_BYTES);
        let clone = lane.clone();
        let slot = lane.reserve_slot().unwrap();
        let job = lane.reserve_job(CONTROL_BYTES).unwrap();
        let before = lane.snapshot().unwrap();
        assert_eq!(clone.begin_shutdown().unwrap(), before);
        assert!(lane.is_shutting_down().unwrap());
        assert!(matches!(lane.reserve_slot(), Err(CredentialIoError::LaneClosed)));
        assert!(matches!(clone.reserve_job(0), Err(CredentialIoError::LaneClosed)));
        assert_eq!(lane.begin_shutdown().unwrap(), before);
        let close = slot.reserve_close().unwrap();
        drop(slot);
        drop(job);
        assert_eq!(lane.snapshot().unwrap().closes, 1);
        drop(close);
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
        assert!(matches!(clone.reserve_slot(), Err(CredentialIoError::LaneClosed)));
    }

    #[test]
    fn drain_waits_for_the_last_owner_worker_mailbox_and_close_charge() {
        let lane = lane(1, 1, CONTROL_BYTES);
        let slot = lane.reserve_slot().unwrap();
        let mailbox = lane.reserve_job(CONTROL_BYTES).unwrap();
        let worker = Arc::clone(&mailbox);
        let close = slot.reserve_close().unwrap();
        lane.begin_shutdown().unwrap();
        let (_registration, mut receiver) = lane.register_observer().unwrap().unwrap();
        drop(mailbox);
        drop(slot);
        assert_eq!(receiver.try_recv(), Err(oneshot::TryRecvError::Empty));
        drop(worker);
        assert_eq!(receiver.try_recv(), Err(oneshot::TryRecvError::Empty));
        drop(close);
        assert_eq!(receiver.try_recv(), Ok(()));
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
    }

    #[test]
    fn drain_observer_is_bounded_and_dropped_registration_cannot_clear_a_successor() {
        let lane = lane(1, 1, CONTROL_BYTES);
        let slot = lane.reserve_slot().unwrap();
        lane.begin_shutdown().unwrap();
        let (first, mut receiver) = lane.register_observer().unwrap().unwrap();
        let first_id = first.id;
        assert!(matches!(lane.register_observer(), Err(CredentialDrainError::ObserverBusy)));
        assert_eq!(lane.inner.state.lock().unwrap().next_observer, first_id);
        drop(first);
        assert_eq!(receiver.try_recv(), Err(oneshot::TryRecvError::Closed));
        let (second, mut receiver) = lane.register_observer().unwrap().unwrap();
        assert_ne!(second.id, first_id);
        // A stale cleanup identity must not erase a different observer.
        drop(DrainRegistration { lane: lane.clone(), id: first_id });
        assert_eq!(receiver.try_recv(), Err(oneshot::TryRecvError::Empty));
        drop(slot);
        assert_eq!(receiver.try_recv(), Ok(()));
    }

    #[test]
    fn observer_id_exhaustion_does_not_reset_or_admit_an_untracked_waiter() {
        let lane = lane(1, 1, CONTROL_BYTES);
        let slot = lane.reserve_slot().unwrap();
        lane.begin_shutdown().unwrap();
        lane.inner.state.lock().unwrap().next_observer = u64::MAX;
        assert!(matches!(lane.register_observer(), Err(CredentialDrainError::ObserverSequenceExhausted)));
        assert!(lane.inner.state.lock().unwrap().waiter.is_none());
        drop(slot);
        assert!(lane.register_observer().unwrap().is_none(), "a drained lane needs no observer allocation");
    }

    #[test]
    fn public_drain_requires_shutdown_valid_timeout_and_caller_timer() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let lane = lane(1, 1, CONTROL_BYTES);
            assert_eq!(lane.wait_drained(&cx, Duration::from_secs(1)).await, Err(CredentialDrainError::ShutdownRequired));
            lane.begin_shutdown().unwrap();
            for timeout in [Duration::ZERO, Duration::from_secs(301), Duration::MAX] {
                assert_eq!(lane.wait_drained(&cx, timeout).await, Err(CredentialDrainError::InvalidTimeout));
            }
            let no_timer = Cx::for_testing();
            assert_eq!(lane.wait_drained(&no_timer, Duration::from_secs(1)).await, Err(CredentialDrainError::TimerUnavailable));
            let cancelled = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
            assert_eq!(lane.wait_drained(&cancelled, Duration::from_secs(1)).await, Err(CredentialDrainError::Cancelled));
            assert!(lane.inner.state.lock().unwrap().waiter.is_none());
            lane.wait_drained(&cx, Duration::from_secs(1)).await.unwrap();
        });
    }

    #[test]
    fn dropping_public_drain_wait_releases_only_the_observer_and_allows_resume() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let lane = lane(1, 1, CONTROL_BYTES);
            let slot = lane.reserve_slot().unwrap();
            lane.begin_shutdown().unwrap();
            let mut wait = Box::pin(lane.wait_drained(&cx, Duration::from_secs(1)));
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(wait.as_mut().poll(&mut context).is_pending());
            assert_eq!(lane.wait_drained(&cx, Duration::from_secs(1)).await, Err(CredentialDrainError::ObserverBusy));
            drop(wait);
            assert!(lane.inner.state.lock().unwrap().waiter.is_none());
            assert_eq!(lane.snapshot().unwrap().slots, 1);
            assert!(lane.is_shutting_down().unwrap());
            drop(slot);
            lane.wait_drained(&cx, Duration::from_secs(1)).await.unwrap();
        });
    }

    #[test]
    fn native_deadline_ends_observation_without_releasing_a_retained_slot() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let lane = lane(1, 1, CONTROL_BYTES);
            let slot = lane.reserve_slot().unwrap();
            lane.begin_shutdown().unwrap();
            assert_eq!(lane.wait_drained(&cx, Duration::from_millis(5)).await, Err(CredentialDrainError::TimedOut));
            assert_eq!(lane.snapshot().unwrap().slots, 1);
            assert!(lane.inner.state.lock().unwrap().waiter.is_none());
            assert!(matches!(lane.reserve_slot(), Err(CredentialIoError::LaneClosed)));
            drop(slot);
            lane.wait_drained(&cx, Duration::from_secs(1)).await.unwrap();
        });
    }

    #[test]
    fn last_release_wakes_a_registered_observer_outside_the_admission_mutex() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};
        struct ReentrantWake { lane: CredentialIoLane, count: AtomicUsize }
        impl Wake for ReentrantWake {
            fn wake(self: Arc<Self>) { self.wake_by_ref(); }
            fn wake_by_ref(self: &Arc<Self>) {
                assert!(self.lane.inner.state.try_lock().is_ok(), "wake must not hold admission mutex");
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let lane = lane(1, 1, CONTROL_BYTES);
            let slot = lane.reserve_slot().unwrap();
            lane.begin_shutdown().unwrap();
            let wake = Arc::new(ReentrantWake { lane: lane.clone(), count: AtomicUsize::new(0) });
            let waker = Waker::from(wake.clone());
            let mut context = std::task::Context::from_waker(&waker);
            let mut wait = Box::pin(lane.wait_drained(&cx, Duration::from_secs(1)));
            assert!(wait.as_mut().poll(&mut context).is_pending());
            assert_eq!(wake.count.load(Ordering::SeqCst), 0);
            drop(slot);
            assert!(wake.count.load(Ordering::SeqCst) > 0, "release must wake before a manual repoll");
            assert_eq!(wait.as_mut().poll(&mut context), Poll::Ready(Ok(())));
        });
    }
}
