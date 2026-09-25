//! Internal admission custody for a store that composes the anchored slot with
//! a synchronous protection provider. Shares the ordinary slot's worker,
//! completion mailbox, overload policy and shutdown domain.

use asupersync::Cx;

use super::admission::{SlotLease, operation_bytes};
use super::{CredentialIoError, CredentialIoLane, CredentialSlotTask, check_submission, spawn, submit};

// Kept crate-private: this is not an arbitrary public blocking-work escape.
// A consumer must bound every captured framework buffer before submission.
// Provider-internal allocations remain the provider's responsibility.
pub(crate) struct ComposedCredentialIo {
    lane: CredentialIoLane,
    working_bytes: usize,
    // Consumer fields must drop before this ownership charge.
    lease: SlotLease,
}

impl ComposedCredentialIo {
    pub(crate) fn reserve(
        cx: &Cx,
        lane: &CredentialIoLane,
        maximum_file_bytes: usize,
        extra_bytes: usize,
    ) -> Result<Self, CredentialIoError> {
        check_submission(cx, &lane.process())?;
        let working_bytes = operation_bytes(maximum_file_bytes)?
            .checked_add(extra_bytes)
            .ok_or(CredentialIoError::InvalidLimits)?;
        let lease = lane.reserve_slot()?;
        Ok(Self { lane: lane.clone(), working_bytes, lease })
    }

    pub(crate) fn submit<T, F>(self, cx: &Cx, work: F)
        -> Result<CredentialSlotTask<T>, CredentialIoError>
    where
        T: Send + 'static,
        F: FnOnce(&Cx, Self) -> T + Send + 'static,
    {
        let lane = self.lane.clone();
        submit(cx, &lane, self.working_bytes, move |worker| work(worker, self))
    }

    // Permit teardown after shutdown and while ordinary work is saturated.
    // No second cancellation domain or cleanup executor is created.
    pub(crate) fn close<T: Send + 'static>(self, cx: &Cx, value: T)
        -> Result<CredentialSlotTask<()>, CredentialIoError>
    {
        let process = self.lane.process();
        check_submission(cx, &process)?;
        let lease = self.lease.reserve_close()?;
        spawn(cx, process, lease, move |_| {
            drop(value);
            drop(self);
        })
    }
}
