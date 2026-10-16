//! Off-poller staging of a complete, owner-bound Task restart selection.
//!
//! All pages and record lookups share one exclusive store owner and one worker
//! admission. A later checkpoint write therefore cannot invalidate a cursor
//! halfway through staging or make a partial selection appear complete.

/// Fresh reconciliation with explicit, persistence-gated result disposition.
pub mod workflow;

use std::fmt;

use asupersync::Cx;

use super::{
    AsyncTaskResumeStore, CredentialSlotTask, TaskResumeBinding, TaskResumeCompletion,
    TaskResumeProtector, TaskResumeSubmissionFailure,
};
use super::super::super::client::restart::{TaskResumeRestartPlan, TaskResumeRestartPolicy};

/// Complete controls loaded under the host's supplied current binding.
///
/// Neither the binding nor the plan is learned from untrusted file metadata.
/// Stored controls still require live authenticated reconciliation; this value
/// never authorizes replay of creation, inputs, cancellation or application work.
/// It retains no file cursor, live response, credential or application result.
#[must_use = "prepare a fresh reconciliation or explicitly retain/discard the staged controls"]
pub struct StagedTaskRestart {
    current: TaskResumeBinding,
    plan: TaskResumeRestartPlan,
}

impl fmt::Debug for StagedTaskRestart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagedTaskRestart")
            .field("records", &self.plan.len())
            .field("charged_bytes", &self.plan.charged_bytes())
            .finish_non_exhaustive()
    }
}

impl StagedTaskRestart {
    pub fn binding(&self) -> &TaskResumeBinding {
        &self.current
    }

    pub fn plan(&self) -> &TaskResumeRestartPlan {
        &self.plan
    }

    /// Transfer the complete selection to the existing read-only restart API.
    /// Later storage writes must still compare the exact staged record version.
    pub fn into_parts(self) -> (TaskResumeBinding, TaskResumeRestartPlan) {
        (self.current, self.plan)
    }
}

impl<P: TaskResumeProtector + 'static> AsyncTaskResumeStore<P> {
    /// Stage every live checkpoint in ONE admitted, caller-owned blocking job.
    ///
    /// This delegates to the same complete, generation-bound enumeration as
    /// TaskResumeRestartPlan::load_store. Count/byte overflow, wrong binding,
    /// cancellation and invalid page size return an error WITH the unchanged
    /// store, never a usable prefix. Expiry between a page and lookup remains
    /// charged by the existing staging rules. No writes or network calls occur.
    ///
    /// Keep the returned task after an interrupted wait: another wait observes
    /// the SAME staging job and owner, not a second scan. Queued/running work and
    /// unread results use the existing lane reservation. The staged controls are
    /// a subset of the bounded manifest, covered by its decoded-copy allowance;
    /// after delivery they become caller-owned memory, like other read results.
    ///
    /// The caller's budget bounds staging. The restart policy's execution
    /// timeout begins when the staged plan is passed to prepare_task_restart,
    /// exactly as for synchronous staging; staging does not start that timer.
    pub fn try_load_restart(
        self,
        cx: &Cx,
        current: TaskResumeBinding,
        page_size: usize,
        policy: TaskResumeRestartPolicy,
    ) -> Result<
        CredentialSlotTask<TaskResumeCompletion<P, StagedTaskRestart>>,
        TaskResumeSubmissionFailure<P, (usize, TaskResumeRestartPolicy)>,
    > {
        self.try_operate(
            cx,
            current,
            (page_size, policy),
            |store, worker, current, (page_size, policy)| {
                let plan = TaskResumeRestartPlan::load_store(
                    worker, current, store, page_size, policy,
                )?;
                Ok(StagedTaskRestart {
                    current: current.clone(),
                    plan,
                })
            },
        )
    }
}
