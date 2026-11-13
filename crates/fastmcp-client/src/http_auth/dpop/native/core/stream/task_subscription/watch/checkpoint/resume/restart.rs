//! Sequential restart of a completely staged, protected DPoP Task selection.
//!
//! The current login, owner binding, original caller and response budget cover
//! the whole batch. Saved controls are lookup hints; they cannot select a
//! transport, renew authority, replay execution or acknowledge result handling.

/// Protected-store acknowledgements with retained completion-mailbox custody.
#[cfg(target_os = "linux")]
pub mod persisted;
#[cfg(target_os = "linux")]
pub use persisted::{
    DpopTaskRestartPreparationFailure, PersistedDpopTaskRestart, PersistedDpopTaskRestartError,
    PersistedDpopTaskRestartParts, PersistedTaskRestartError, RestartCheckpointState,
};

#[cfg(test)]
mod tests;
#[cfg(all(test, feature = "native-tls-roots"))]
mod tls;

use std::collections::VecDeque;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::time::{Duration, Instant};

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::FinalRequestMeta;

use super::super::super::{DpopTaskWatchError, DpopTaskWatchPolicy, WatchState};
use super::{
    DpopTaskResumeError, DpopTaskResumeSnapshot, TaskResumeBinding, TaskResumeChange,
    TaskResumeError, TaskResumeRecord,
};
use crate::http_auth::caller::with_caller;
use crate::http_auth::dpop::native::core::stream::DpopStreamLimits;
use crate::http_auth::dpop::native::core::stream::budget::SharedStreamBudget;
use crate::http_auth::dpop::native::{
    DpopCredential, DpopHttpClient, DpopHttpError, WaitBounds, check_live_owner, require_runtime,
    within_owner,
};

pub use crate::http_auth::managed::tasks::watch::checkpoint::resume::client::restart::{
    TaskResumeRestartPlan, TaskResumeRestartPolicy,
};

/// Only local expiry and remote HTTP 401/403/404 produce Unavailable. A malformed
/// reply, failed transport, exhausted budget or operational error closes the
/// restart rather than silently skipping a saved Task.
#[allow(
    clippy::large_enum_variant,
    reason = "outcomes are produced one at a time and retained in one pending slot; the plan stores only control records"
)]
pub enum DpopTaskRestartOutcome {
    Reconciled(DpopTaskResumeSnapshot),
    Unavailable,
}

impl fmt::Debug for DpopTaskRestartOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reconciled(snapshot) => f.debug_tuple("Reconciled").field(snapshot).finish(),
            Self::Unavailable => f.write_str("Unavailable"),
        }
    }
}

/// The exact saved version and its freshly authenticated, payload-bearing
/// outcome. Neither this item nor its outcome is Clone or serializable.
pub struct DpopTaskRestartItem {
    pub previous: TaskResumeRecord,
    pub outcome: DpopTaskRestartOutcome,
}

impl fmt::Debug for DpopTaskRestartItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopTaskRestartItem")
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl DpopTaskRestartItem {
    /// Prepare the exact-version local checkpoint change AFTER handling or
    /// durably recording any terminal result. This does not perform storage.
    /// An unavailable outcome prepares explicit removal of the old controls;
    /// it never proves that remote work stopped or authorizes creating it again.
    ///
    /// Publicly assembled items are checked again against the current owner,
    /// saved version and fresh controls. No application payload enters a change.
    /// A terminal whose saved retention expired while the host handled it needs
    /// an explicit TaskResumeChange::discard disposition rather than renewed
    /// resume authority.
    pub fn storage_change(
        &self,
        cx: &Cx,
        current: &TaskResumeBinding,
    ) -> Result<TaskResumeChange, TaskResumeError> {
        match &self.outcome {
            DpopTaskRestartOutcome::Unavailable => {
                TaskResumeChange::discard(cx, current, &self.previous)
            }
            DpopTaskRestartOutcome::Reconciled(snapshot) => {
                let change = TaskResumeChange::from_snapshot(
                    cx,
                    current,
                    &self.previous,
                    &snapshot.snapshot().task,
                )?;
                if snapshot.change().previous() != &self.previous
                    || snapshot.change().replacement() != change.replacement()
                {
                    return Err(TaskResumeError::ConflictingSnapshot);
                }
                match (change.replacement(), snapshot.selection()) {
                    (None, None) => {}
                    (Some(record), Some(selection))
                        if selection.resource().as_str() == current.resource().as_str()
                            && selection.task_id() == record.task_id() => {}
                    _ => return Err(TaskResumeError::ConflictingSnapshot),
                }
                Ok(change)
            }
        }
    }
}

#[derive(Debug)]
pub enum DpopTaskRestartError {
    Resume(DpopTaskResumeError),
    CallerMismatch,
    Closed,
}

impl fmt::Display for DpopTaskRestartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resume(error) => error.fmt(f),
            Self::CallerMismatch => f.write_str("DPoP Task restart caller does not match"),
            Self::Closed => f.write_str(
                "DPoP Task restart owner is closed; reconcile its pending read explicitly",
            ),
        }
    }
}

impl std::error::Error for DpopTaskRestartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resume(error) => Some(error),
            Self::CallerMismatch | Self::Closed => None,
        }
    }
}

impl From<DpopTaskResumeError> for DpopTaskRestartError {
    fn from(error: DpopTaskResumeError) -> Self {
        Self::Resume(error)
    }
}
impl From<TaskResumeError> for DpopTaskRestartError {
    fn from(error: TaskResumeError) -> Self {
        Self::Resume(error.into())
    }
}
impl From<DpopHttpError> for DpopTaskRestartError {
    fn from(error: DpopHttpError) -> Self {
        Self::Resume(error.into())
    }
}
impl From<DpopTaskWatchError> for DpopTaskRestartError {
    fn from(error: DpopTaskWatchError) -> Self {
        Self::Resume(error.into())
    }
}

// Keep the original caller alive across returns and host checkpoint pauses.
// A wall ceiling prevents a different/idle timer from extending the admitted
// lifetime. Each supplied caller can only narrow the retained deadline/effects.
struct RestartBounds {
    caller: Cx,
    bounds: WaitBounds,
    expires_at: Instant,
}

impl RestartBounds {
    fn new(cx: &Cx, timeout: Duration, credential: &DpopCredential) -> Result<Self, DpopHttpError> {
        with_caller(cx, || {
            let caller = Cx::current().ok_or(DpopHttpError::RuntimeUnavailable)?;
            let wall = Instant::now();
            let bounds = WaitBounds::new(&caller, timeout, credential)?;
            let remaining = Duration::from_nanos(
                bounds
                    .deadline
                    .as_nanos()
                    .saturating_sub(caller.now().as_nanos()),
            );
            let lifetime = Self {
                caller,
                bounds,
                expires_at: wall
                    .checked_add(remaining)
                    .ok_or(DpopHttpError::InvalidPolicy)?,
            };
            lifetime.check_ceiling()?;
            Ok(lifetime)
        })
    }

    fn tighten(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        owner: &McpRequestCancellation,
        credential: &DpopCredential,
    ) -> Result<WaitBounds, DpopTaskRestartError> {
        if cx.task_id() != self.caller.task_id() || cx.region_id() != self.caller.region_id() {
            return Err(DpopTaskRestartError::CallerMismatch);
        }
        with_caller(cx, || {
            check_live_owner(&self.caller, cancellation, owner, credential, self.bounds)?;
            self.check_ceiling()?;
            let wall = Instant::now();
            let remaining = self.expires_at.saturating_duration_since(wall);
            if remaining.is_zero() {
                return Err(self.bounds.terminal.into());
            }
            let supplied = WaitBounds::new(cx, remaining, credential)?;
            let remaining = Duration::from_nanos(
                supplied
                    .deadline
                    .as_nanos()
                    .saturating_sub(cx.now().as_nanos()),
            );
            let expiry = wall
                .checked_add(remaining)
                .ok_or(DpopHttpError::InvalidPolicy)?;
            if expiry < self.expires_at {
                self.expires_at = expiry;
                let remaining = expiry.saturating_duration_since(Instant::now());
                let deadline = self
                    .caller
                    .now()
                    .saturating_add_nanos(u64::try_from(remaining.as_nanos()).unwrap_or(u64::MAX));
                if deadline < self.bounds.deadline {
                    self.bounds = WaitBounds {
                        deadline,
                        terminal: supplied.terminal,
                    };
                }
            }
            self.check(cx, cancellation, owner, credential, supplied)?;
            Ok(supplied)
        })
    }

    fn check_ceiling(&self) -> Result<(), DpopHttpError> {
        if Instant::now() >= self.expires_at {
            return Err(self.bounds.terminal);
        }
        require_runtime(&self.caller)?;
        let active = Cx::current().ok_or(DpopHttpError::RuntimeUnavailable)?;
        let available = active.capabilities();
        let held = self.caller.capabilities();
        if !available.entropy
            || (held.spawn && !available.spawn)
            || (held.remote && !available.remote)
        {
            return Err(DpopHttpError::RuntimeUnavailable);
        }
        Ok(())
    }

    fn check(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        owner: &McpRequestCancellation,
        credential: &DpopCredential,
        supplied: WaitBounds,
    ) -> Result<(), DpopHttpError> {
        check_live_owner(&self.caller, cancellation, owner, credential, self.bounds)?;
        check_live_owner(cx, cancellation, owner, credential, supplied)?;
        with_caller(cx, || self.check_ceiling())
    }

    async fn during<T>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        owner: &McpRequestCancellation,
        credential: &DpopCredential,
        supplied: WaitBounds,
        future: impl Future<Output = Result<T, DpopHttpError>>,
    ) -> Result<T, DpopHttpError> {
        let mut future = pin!(future);
        // Both callers have independent cancellation wakeups. Tightening the
        // original timer also enforces a shorter supplied deadline even when
        // that supplied caller's timer belongs to an idle runtime.
        within_owner(
            cx,
            cancellation,
            owner,
            credential,
            supplied,
            within_owner(
                &self.caller,
                cancellation,
                owner,
                credential,
                self.bounds,
                poll_fn(|task| {
                    self.check_ceiling()?;
                    let result = future.as_mut().poll(task);
                    self.check_ceiling()?;
                    result
                }),
            ),
        )
        .await
    }
}

impl DpopHttpClient {
    /// Admit an entire staged selection against CURRENT host-verified owner
    /// facts and this explicitly chosen DPoP login before making any request.
    /// The host must associate the binding with the chosen credential; neither
    /// stored identity nor a Task ID establishes remote authorization.
    ///
    /// The batch uses the minimum of plan, core, native, caller and original
    /// credential lifetimes. Pausing to handle/persist an item does not renew
    /// those bounds. A single aggregate discovery/payload/notification ledger
    /// covers all reads, including responses classified as Unavailable. Raw
    /// HTTP body and parser limits retain their existing per-response bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_task_restart<'client>(
        &'client mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        current: TaskResumeBinding,
        plan: TaskResumeRestartPlan,
        id_prefix: String,
        limits: DpopStreamLimits,
    ) -> Result<DpopTaskRestart<'client>, DpopTaskRestartError> {
        let (records, timeout) = plan.into_bound_parts(&current, self.resource().as_str())?;
        let state = WatchState::new(
            &id_prefix,
            DpopTaskWatchPolicy::new(records.len().max(1))?,
            limits,
        )?;
        let lifetime = RestartBounds::new(
            cx,
            timeout.min(self.policy.timeout).min(limits.core.timeout()),
            credential,
        )?;
        check_live_owner(
            &lifetime.caller,
            cancellation,
            &self.session.cancellation,
            credential,
            lifetime.bounds,
        )?;
        let budget =
            SharedStreamBudget::new(limits.core, (0, 0)).map_err(DpopTaskWatchError::from)?;
        let finished = records.is_empty();
        Ok(DpopTaskRestart {
            client: self,
            current,
            records,
            state,
            budget,
            metadata,
            cancellation: cancellation.clone(),
            credential: credential.clone(),
            lifetime,
            pending_record: None,
            pending_outcome: None,
            ready: !finished,
            finished,
            attempted: 0,
            delivered: 0,
        })
    }
}

/// Exclusive, caller-driven custody of one protected restart. Each eligible
/// record gets fresh authenticated discovery and one tasks/get. No worker,
/// watch, automatic refresh, storage write or remote mutation is started.
///
/// A failed or abandoned POLLED read permanently closes this owner. Its
/// current record, any fully returned result and all unvisited records remain
/// inspectable. An unpolled future has no effect. No operational failure is
/// automatically retried; Unavailable is an explicit deliverable disposition.
#[must_use = "drive reconciliations or retain the remaining Task controls"]
pub struct DpopTaskRestart<'client> {
    client: &'client mut DpopHttpClient,
    current: TaskResumeBinding,
    records: VecDeque<TaskResumeRecord>,
    state: WatchState,
    budget: SharedStreamBudget,
    metadata: FinalRequestMeta,
    cancellation: McpRequestCancellation,
    credential: DpopCredential,
    lifetime: RestartBounds,
    pending_record: Option<TaskResumeRecord>,
    pending_outcome: Option<DpopTaskRestartOutcome>,
    ready: bool,
    finished: bool,
    attempted: usize,
    delivered: usize,
}

impl fmt::Debug for DpopTaskRestart<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopTaskRestart")
            .field("remaining", &self.remaining())
            .field("attempted", &self.attempted)
            .field("delivered", &self.delivered)
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

impl DpopTaskRestart<'_> {
    pub fn remaining(&self) -> usize {
        self.records.len() + usize::from(self.pending_record.is_some())
    }
    /// Reads started; a locally expired record consumes no request.
    pub fn attempted(&self) -> usize {
        self.attempted
    }
    pub fn delivered(&self) -> usize {
        self.delivered
    }
    pub fn pending_record(&self) -> Option<&TaskResumeRecord> {
        self.pending_record.as_ref()
    }
    pub fn pending_outcome(&self) -> Option<&DpopTaskRestartOutcome> {
        self.pending_outcome.as_ref()
    }
    pub fn unvisited(&self) -> impl ExactSizeIterator<Item = &TaskResumeRecord> {
        self.records.iter()
    }
    pub fn is_closed(&self) -> bool {
        !self.ready && !self.finished
    }
    pub fn close(&mut self) {
        self.ready = false;
    }

    /// Explicitly extract a failed/abandoned read's custody. The owner stays
    /// closed and retains its unvisited controls; no read or write is retried.
    pub fn take_pending(&mut self) -> Option<(TaskResumeRecord, Option<DpopTaskRestartOutcome>)> {
        self.ready = false;
        self.pending_record
            .take()
            .map(|record| (record, self.pending_outcome.take()))
    }

    /// Read under the original caller's task/region identity. A supplied caller
    /// can narrow its budget or effect ceiling; it cannot replace the original
    /// cancellation domain, credential lifetime or absolute batch deadline.
    pub async fn next_reconciled(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<DpopTaskRestartItem>, DpopTaskRestartError> {
        if self.finished {
            return Ok(None);
        }
        if !self.ready {
            return Err(DpopTaskRestartError::Closed);
        }
        // Elect custody before any fallible work or suspension. A dropped
        // polled future cannot put its selected record back into the queue.
        self.ready = false;
        let owner = self.client.session.cancellation.clone();
        let supplied = self
            .lifetime
            .tighten(cx, &self.cancellation, &owner, &self.credential)?;
        let Some(record) = self.records.pop_front() else {
            self.finished = true;
            return Ok(None);
        };
        self.pending_record = Some(record);
        let pending = self
            .pending_record
            .as_ref()
            .ok_or(TaskResumeError::InvalidRecord)?;
        match pending.admit(&self.lifetime.caller, &self.current) {
            Err(TaskResumeError::Unavailable) => {
                self.pending_outcome = Some(DpopTaskRestartOutcome::Unavailable);
            }
            Err(error) => return Err(error.into()),
            Ok(()) => {
                self.attempted += 1;
                let outcome = &mut self.pending_outcome;
                let client = &mut self.client;
                let caller = &self.lifetime.caller;
                let bounds = self.lifetime.bounds;
                let cancellation = &self.cancellation;
                let credential = &self.credential;
                let current = &self.current;
                let metadata = self.metadata.clone();
                let state = &mut self.state;
                let budget = self.budget.clone();
                self.lifetime
                    .during(cx, cancellation, &owner, credential, supplied, async {
                        let observed = client
                            .reconcile_task_resume_with_state(
                                caller,
                                cancellation,
                                credential,
                                metadata,
                                current,
                                pending,
                                bounds,
                                state,
                                Some(budget),
                                &mut |_| true,
                            )
                            .await;
                        let observed = match observed {
                            Ok(snapshot) => DpopTaskRestartOutcome::Reconciled(snapshot),
                            Err(DpopTaskResumeError::Resume(TaskResumeError::Unavailable)) => {
                                DpopTaskRestartOutcome::Unavailable
                            }
                            Err(error) => return Ok(Err(error)),
                        };
                        // A result returned by the reconciler is owned BEFORE
                        // outer deadline/cancellation checks can refuse delivery.
                        *outcome = Some(observed);
                        Ok(Ok(()))
                    })
                    .await??;
            }
        }
        self.lifetime
            .check(cx, &self.cancellation, &owner, &self.credential, supplied)?;
        let previous = self
            .pending_record
            .take()
            .ok_or(TaskResumeError::InvalidRecord)?;
        let outcome = self
            .pending_outcome
            .take()
            .ok_or(TaskResumeError::InvalidRecord)?;
        self.delivered += 1;
        self.finished = self.records.is_empty();
        self.ready = !self.finished;
        Ok(Some(DpopTaskRestartItem { previous, outcome }))
    }
}
