//! Caller-owned capacity for asynchronous credential storage.
//!
//! Share one lane across the stores in an application admission domain. Cloning
//! a lane shares its counters; it does not create another budget. Applications
//! creating independent lanes are responsible for their aggregate process cap.
//! No thread pool, runtime, background waiter or global registry is introduced.

use std::fmt;
use std::sync::{Arc, Mutex};

use fastmcp_core::runtime::{ProcessBoundToken, ProcessGenerationGuard};

use super::CredentialIoError;

const MAX_SLOTS: usize = 1_024;
const MAX_OPERATIONS: usize = 256;
const MAX_RESERVED_BYTES: usize = 256 * 1024 * 1024;
pub(super) const CONTROL_BYTES: usize = 16 * 1024;

/// Bounds for retained file owners, ordinary jobs and their framework buffers.
/// Jobs include queued/running work AND completions not yet received or dropped.
/// Provider-internal memory and application-owned returned values are outside
/// the byte charge; the provider must separately bound its own memory and I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialIoLimits {
    maximum_slots: usize,
    maximum_operations: usize,
    maximum_reserved_bytes: usize,
}

impl Default for CredentialIoLimits {
    fn default() -> Self {
        Self { maximum_slots: 128, maximum_operations: 32, maximum_reserved_bytes: 16 * 1024 * 1024 }
    }
}

impl CredentialIoLimits {
    pub fn new(slots: usize, operations: usize, bytes: usize) -> Result<Self, CredentialIoError> {
        if slots == 0 || slots > MAX_SLOTS || operations == 0 || operations > MAX_OPERATIONS
            || bytes < CONTROL_BYTES || bytes > MAX_RESERVED_BYTES
        {
            return Err(CredentialIoError::InvalidLimits);
        }
        Ok(Self { maximum_slots: slots, maximum_operations: operations, maximum_reserved_bytes: bytes })
    }

    pub fn maximum_slots(self) -> usize { self.maximum_slots }
    pub fn maximum_operations(self) -> usize { self.maximum_operations }
    pub fn maximum_reserved_bytes(self) -> usize { self.maximum_reserved_bytes }
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

struct LaneInner {
    process: Arc<ProcessBoundToken>,
    limits: CredentialIoLimits,
    // Only fixed-size counter arithmetic under this mutex. Never call a
    // provider, filesystem, runtime, destructor or user Waker while holding it.
    state: Mutex<CredentialIoSnapshot>,
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
            process: Arc::new(guard.token()), limits, state: Mutex::new(CredentialIoSnapshot::default()),
        }) })
    }

    pub fn limits(&self) -> CredentialIoLimits { self.inner.limits }

    pub fn snapshot(&self) -> Result<CredentialIoSnapshot, CredentialIoError> {
        self.verify()?;
        self.inner.state.lock().map(|state| *state).map_err(|_| CredentialIoError::AdmissionUnavailable)
    }

    pub(super) fn process(&self) -> Arc<ProcessBoundToken> { Arc::clone(&self.inner.process) }

    fn verify(&self) -> Result<(), CredentialIoError> {
        // Check before accessing a possibly inherited locked mutex after fork.
        self.inner.process.verify().map_err(|_| CredentialIoError::ProcessChanged)
    }

    pub(super) fn reserve_slot(&self) -> Result<SlotLease, CredentialIoError> {
        self.verify()?;
        let mut state = self.inner.state.lock().map_err(|_| CredentialIoError::AdmissionUnavailable)?;
        if state.slots >= self.inner.limits.maximum_slots { return Err(CredentialIoError::CapacityExceeded); }
        state.slots += 1;
        Ok(SlotLease { lane: self.clone() })
    }

    pub(super) fn reserve_job(&self, bytes: usize) -> Result<Arc<JobLease>, CredentialIoError> {
        self.verify()?;
        let mut state = self.inner.state.lock().map_err(|_| CredentialIoError::AdmissionUnavailable)?;
        let total = state.reserved_bytes.checked_add(bytes).ok_or(CredentialIoError::CapacityExceeded)?;
        if state.operations >= self.inner.limits.maximum_operations || total > self.inner.limits.maximum_reserved_bytes {
            return Err(CredentialIoError::CapacityExceeded);
        }
        // Both dimensions commit together. A byte refusal cannot consume a job.
        state.operations += 1;
        state.reserved_bytes = total;
        Ok(Arc::new(JobLease { lane: self.clone(), bytes, closing: false }))
    }
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
        if state.closes >= self.lane.inner.limits.maximum_slots { return Err(CredentialIoError::CapacityExceeded); }
        state.closes += 1;
        Ok(Arc::new(JobLease { lane: self.lane.clone(), bytes: 0, closing: true }))
    }
}
impl Drop for SlotLease {
    fn drop(&mut self) {
        if self.lane.verify().is_err() { return; }
        if let Ok(mut state) = self.lane.inner.state.lock() {
            state.slots -= 1;
        }
    }
}

/// Shared by the task owner and worker. Dropping a wait/task cannot release
/// capacity while a non-preemptible provider is still executing. Conversely,
/// worker completion cannot release an unread result's retained byte charge.
pub(super) struct JobLease { lane: CredentialIoLane, bytes: usize, closing: bool }
impl Drop for JobLease {
    fn drop(&mut self) {
        if self.lane.verify().is_err() { return; }
        if let Ok(mut state) = self.lane.inner.state.lock() {
            if self.closing {
                state.closes -= 1;
            } else {
                state.operations -= 1;
                state.reserved_bytes -= self.bytes;
            }
        }
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
}
