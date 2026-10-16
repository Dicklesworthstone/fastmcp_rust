//! Capability-gated host input on the existing event-driven DPoP Task watch.
//!
//! Only authoritative get snapshots can request host work. The subscription
//! remains open during resolution and update; a successful update is followed
//! by an immediate get, without waiting for a possibly coalesced status event.

/// Create one tool invocation and continue on the same bounded subscription run.
pub mod start;

use std::collections::BTreeMap;
use std::future::{Future, Ready, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::task::Poll;
use std::time::Duration;

use fastmcp_core::Sha256Digest;
use fastmcp_protocol::tasks_extension::{TaskInputRequests, TaskInputResponses};
use serde_json::Value;

use super::*;
use crate::http_auth::managed::tasks::driver::{
    DriverState, ManagedTaskDriverPolicy, admit_capabilities, validate_answers,
};
pub use crate::http_auth::managed::tasks::driver::{
    ManagedTaskDriverError, ManagedTaskInputAction,
};

/// Finite limits for snapshots, host input, and the entire subscription drive.
/// Input fingerprints, not answers or a replayable continuation, are retained.
#[derive(Clone, Copy, Debug)]
pub struct DpopTaskWatchDriverPolicy {
    watch: DpopTaskWatchPolicy,
    input: ManagedTaskDriverPolicy,
}

impl Default for DpopTaskWatchDriverPolicy {
    fn default() -> Self {
        Self {
            watch: DpopTaskWatchPolicy::default(),
            input: ManagedTaskDriverPolicy::default(),
        }
    }
}

impl DpopTaskWatchDriverPolicy {
    pub(in crate::http_auth::dpop::native::core) fn timeout(self) -> Duration {
        self.input.timeout
    }

    // Preflight arbitrary creating IDs against the COMPLETE bounded future
    // namespace, before a tool can create remote work. Conversation successor
    // IDs use colons and are disjoint from these dot-separated watch IDs.
    pub(in crate::http_auth::dpop::native::core) fn admit_creation_ids(
        self, prefix: &str, ids: [&RequestId; 2],
    ) -> Result<(), DpopTaskWatchError> {
        let check = |candidate: String| {
            let candidate = RequestId::String(candidate);
            if ids.iter().any(|id| id.correlates_with(&candidate)) {
                Err(DpopTaskWatchError::from(ManagedTaskDriverError::RepeatedRequestId))
            } else { Ok(()) }
        };
        check(format!("{prefix}.listen.discover"))?;
        check(format!("{prefix}.listen"))?;
        // A creating call may not borrow an identity that will be used only
        // after a later clean rollover. Reserve the whole configured namespace
        // before creation, not when the already-created Task reconnects.
        let reconnects = self.watch.reconnect.map_or(0, |policy| policy.maximum_reconnects);
        for index in 1..=reconnects {
            check(format!("{prefix}.listen.{index}.discover"))?;
            check(format!("{prefix}.listen.{index}"))?;
        }
        for index in 0..self.watch.maximum_snapshots {
            check(format!("{prefix}.{index}.discover"))?;
            check(format!("{prefix}.{index}.get"))?;
        }
        for index in 0..self.input.maximum_updates {
            check(format!("{prefix}.input.{index}.discover"))?;
            check(format!("{prefix}.input.{index}.update"))?;
        }
        Ok(())
    }

    /// Allows 1..=1024 gets, 0..=128 updates, 0..=4096 input keys,
    /// 1..=4 MiB of retained input-key/fingerprint bytes and a nonzero timeout
    /// of at most 24 hours. Zero updates makes input-required a host handoff.
    /// No polling interval exists: gets follow acknowledgement, status hints,
    /// accepted updates, or clean subscription completion, never a timer.
    pub fn new(
        maximum_snapshots: usize,
        maximum_updates: usize,
        maximum_input_keys: usize,
        maximum_state_bytes: usize,
        timeout: Duration,
    ) -> Result<Self, DpopTaskWatchError> {
        let watch = DpopTaskWatchPolicy::new(maximum_snapshots)?;
        // Reuse the shared input-ledger policy admission. Its interval and
        // polling counter are unused; WatchState owns snapshot scheduling.
        let input = ManagedTaskDriverPolicy::new(
            Duration::from_secs(1), timeout, maximum_snapshots, maximum_updates,
            maximum_input_keys, maximum_state_bytes,
        ).map_err(|_| DpopTaskWatchError::InvalidPolicy)?;
        Ok(Self { watch, input })
    }

    /// Continue observation across bounded clean subscription rollovers.
    /// After the first listen ends, successors can observe but cannot invoke
    /// the input resolver or send updates. Fresh input-required state returns
    /// to the host for explicit disposition; old answers are never replayed.
    /// Creating-call adapters reserve every successor request ID in advance.
    /// The same operation deadline, credential and aggregate quotas remain.
    pub fn with_reconnects(
        mut self,
        maximum_reconnects: usize,
        minimum_delay: Duration,
    ) -> Result<Self, DpopTaskWatchError> {
        self.watch = self.watch.with_reconnects(maximum_reconnects, minimum_delay)?;
        Ok(self)
    }

    /// Opt into observation-only polling after a clean subscription ending.
    /// Task-input mutation authority is not restored once the listen is gone.
    /// When reconnection is selected, polling follows its exhausted allowance.
    pub fn with_polling_fallback(
        mut self,
        maximum_polls: usize,
        minimum_poll_interval: Duration,
    ) -> Result<Self, DpopTaskWatchError> {
        self.watch = self.watch.with_polling_fallback(
            maximum_polls, minimum_poll_interval,
        )?;
        Ok(self)
    }
}

impl From<ManagedTaskDriverError> for DpopTaskWatchError {
    fn from(error: ManagedTaskDriverError) -> Self { Self::Driver(error) }
}

// Concrete generic callbacks keep Send conditional on the host's own types,
// instead of introducing a boxed/dynamic future or requiring a Send-only host.
pub(super) type NoInput = InputDriver<
    fn(TaskInputRequests) -> Ready<Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
    fn(&Task) -> Result<(), ManagedTaskDriverError>,
>;

pub(super) enum InputDecision {
    Return,
    Wait,
    Update(TaskInputResponses),
}

struct PendingAnswers {
    keys: Vec<String>,
    fingerprints: BTreeMap<String, Sha256Digest>,
}

pub(super) struct InputDriver<R, O> {
    policy: ManagedTaskDriverPolicy,
    ledger: DriverState,
    updates: usize,
    pending: Option<PendingAnswers>,
    metadata: Value,
    resolve: R,
    observe: O,
}

fn check(life: &Lifetime<'_>) -> Result<(), DpopTaskWatchError> {
    check_live(life.cx, life.cancellation, life.session, life.credential, life.bounds)?;
    Ok(())
}

// Catch host panics without retaining their payload. Check lifetime after the
// callback even when it refuses or panics; cancellation/revocation still wins.
fn callback<T>(life: &Lifetime<'_>, call: impl FnOnce() -> T)
    -> Result<T, DpopTaskWatchError>
{
    check(life)?;
    let result = with_caller(life.cx, || catch_unwind(AssertUnwindSafe(call)));
    check(life)?;
    result.map_err(|_| DpopStreamError::ObserverPanicked.into())
}

impl<R, O> InputDriver<R, O> {
    fn new(
        policy: ManagedTaskDriverPolicy, metadata: &FinalRequestMeta, resolve: R, observe: O,
    ) -> Result<Self, DpopTaskWatchError> {
        Ok(Self {
            policy, ledger: DriverState::default(), updates: 0, pending: None,
            metadata: serde_json::to_value(metadata).map_err(|_| ManagedCoreError::InvalidRequest)?,
            resolve, observe,
        })
    }

    fn stage(
        &mut self, requests: &TaskInputRequests,
        fingerprints: BTreeMap<String, Sha256Digest>, responses: &TaskInputResponses,
    ) -> Result<(), DpopTaskWatchError> {
        if self.pending.is_some() {
            return Err(ManagedTaskDriverError::UnexpectedResponse.into());
        }
        validate_answers(requests, responses)?;
        let keys: Vec<_> = responses.keys().cloned().collect();
        // Never send answers which cannot be remembered after acknowledgement.
        self.ledger.answer_bytes(&keys, &fingerprints, self.policy.maximum_state_bytes)?;
        self.pending = Some(PendingAnswers { keys, fingerprints });
        Ok(())
    }

    pub(super) fn update_request(
        &mut self, watch: &WatchState, task: Task, responses: TaskInputResponses,
    ) -> Result<(DpopTaskOperation, DpopStreamLimits), DpopTaskWatchError> {
        if self.pending.is_none() {
            return Err(ManagedTaskDriverError::UnexpectedResponse.into());
        }
        if self.updates >= self.policy.maximum_updates {
            return Err(ManagedTaskDriverError::UpdateLimit.into());
        }
        watch.require_snapshot()?;
        let limits = watch.remaining_limits()?;
        // The fixed "input" segment is disjoint from numbered gets and listen.
        // Bounded monotonic counters therefore need no retained ID history.
        let operation = DpopTaskOperation::new(
            RequestId::String(format!("{}.input.{}.discover", watch.prefix, self.updates)),
            RequestId::String(format!("{}.input.{}.update", watch.prefix, self.updates)),
            ManagedTaskRequest::Update { task: Box::new(task), input_responses: responses },
        )?;
        self.updates += 1;
        Ok((operation, limits))
    }

    pub(super) fn acknowledged(&mut self) -> Result<(), DpopTaskWatchError> {
        let pending = self.pending.as_ref().ok_or(ManagedTaskDriverError::UnexpectedResponse)?;
        self.ledger.record_answers(
            &pending.keys, &pending.fingerprints, self.policy.maximum_state_bytes,
        )?;
        self.pending = None;
        Ok(())
    }

    pub(super) async fn on_snapshot<F>(
        &mut self, life: &Lifetime<'_>, watch: &WatchState, task: &Task, may_update: bool,
    ) -> Result<InputDecision, DpopTaskWatchError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        callback(life, || (self.observe)(task))??;
        let Task::InputRequired { input_requests, .. } = task else {
            return Ok(if matches!(task, Task::Working(_)) {
                InputDecision::Wait
            } else { InputDecision::Return });
        };
        // A finished listen cannot grant a new mutation or resolver invocation.
        // Preserve the complete final snapshot for explicit host handling.
        if !may_update || self.policy.maximum_updates == 0 {
            return Ok(InputDecision::Return);
        }
        let (pending, fingerprints) = self.ledger.unanswered(input_requests, self.policy)?;
        if pending.is_empty() { return Ok(InputDecision::Wait); }
        if self.updates >= self.policy.maximum_updates {
            return Err(ManagedTaskDriverError::UpdateLimit.into());
        }
        watch.require_snapshot()?;
        watch.remaining_limits()?;
        let inputs = admit_capabilities(&self.metadata, &pending)?;
        // A constructor may revoke authority. Guard construction separately so
        // its returned future is never polled after that revocation.
        let resolution = callback(life, || (self.resolve)(inputs))?;
        let mut resolution = std::pin::pin!(resolution);
        let action = within(
            life.cx, life.cancellation, life.session, life.credential, life.bounds, async {
                Ok(poll_fn(|context| {
                    match catch_unwind(AssertUnwindSafe(|| resolution.as_mut().poll(context))) {
                        Ok(Poll::Pending) => Poll::Pending,
                        Ok(Poll::Ready(result)) => Poll::Ready(result.map_err(DpopTaskWatchError::from)),
                        Err(_) => Poll::Ready(Err(DpopStreamError::ObserverPanicked.into())),
                    }
                }).await)
            },
        ).await??;
        check(life)?;
        match action {
            ManagedTaskInputAction::ReturnToCaller => Ok(InputDecision::Return),
            ManagedTaskInputAction::Respond(responses) => {
                self.stage(&pending, fingerprints, &responses)?;
                check(life)?;
                Ok(InputDecision::Update(responses))
            }
        }
    }
}

impl DpopHttpClient {
    // Only an admitted creating conversation can call this handoff. Publish
    // its Task ID before any successor POST, then preserve the exact original
    // bounds and charges; this method is not a public restart capability.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::http_auth::dpop::native::core) async fn drive_created_task_with_subscription<R, F, O>(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
        credential: &DpopCredential, metadata: FinalRequestMeta, task: Task,
        id_prefix: &str, policy: DpopTaskWatchDriverPolicy, limits: DpopStreamLimits,
        bounds: WaitBounds, initial_usage: (usize, usize), resolve: R, observe: O,
    ) -> Result<Option<DpopTaskWaitOutcome>, DpopTaskWatchError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let mut input = InputDriver::new(policy.input, &metadata, resolve, observe)?;
        let life = Lifetime { cx, cancellation, session: &self.session, credential, bounds };
        callback(&life, || (input.observe)(&task))??;
        if matches!(&task, Task::Completed { .. } | Task::Failed { .. } | Task::Cancelled(_)) {
            return Ok(None);
        }
        let task_id = task.base().task_id.clone();
        self.watch_task_using(
            cx, cancellation, credential, metadata, task_id, id_prefix,
            policy.watch, limits, bounds, initial_usage, Some(input),
        ).await.map(Some)
    }

    /// Drive an existing Task using subscriptions and explicit, typed host input.
    ///
    /// Uses the SAME get/acknowledge/reconcile watch as observation-only waiting.
    /// Observers see authoritative get snapshots, never status hints. Only new,
    /// capability-admitted input keys reach the resolver; sampling context is
    /// normalized by the shared Task driver. Empty, foreign, already-answered,
    /// or type-mismatched answers fail before discovery or update dispatch.
    ///
    /// Successful updates require a method-owned ACK and clean JSON/SSE EOF
    /// before the shared input ledger advances. Every accepted update causes
    /// an immediate fresh get: no event is needed to finish the input round.
    /// Unchanged acknowledged inputs do not repeat host work or an update;
    /// reusing an acknowledged key for a changed descriptor fails closed.
    /// Partial answers are supported. A failed/uncertain update ends the run
    /// without replay, reconciliation, automatic reconnect, or remote cancel.
    ///
    /// Input can be serviced before subscribing. Once the listen opens, it
    /// stays owned during resolver and update waits. Its original idle deadline
    /// bounds those waits too; status hints, updates and host callbacks never
    /// extend it. All discovery/get/update/listen payloads and notifications
    /// share ONE byte/count budget, original credential, and absolute deadline.
    /// Get/update progress is admitted and charged, not delivered as a snapshot.
    /// A quiet listen sends no periodic gets. After clean listen completion,
    /// the final get and any explicitly configured successors are observation-only:
    /// input-required returns to the host, even if the input ledger has capacity.
    /// Reconnection never carries the former listen's mutation authority forward.
    ///
    /// ReturnToCaller and a zero-update policy return the full input snapshot,
    /// including metadata. Failed/cancelled Tasks retain their terminal variants.
    /// Host errors, panics, cancellation, revocation and dropping the future stop
    /// local work and release both owned exchanges, not the shared login. The
    /// host's panic hook and effects already performed cannot be undone.
    ///
    /// Use a fresh bounded id_prefix for every run. The input ledger lives only
    /// in this future; restarting is explicit host authority, NOT an exactly-once
    /// promise or a checkpoint containing reusable input-answer authority.
    #[allow(clippy::too_many_arguments)]
    pub async fn drive_task_with_subscription<R, F, O>(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
        credential: &DpopCredential, metadata: FinalRequestMeta, task: TaskId,
        id_prefix: &str, policy: DpopTaskWatchDriverPolicy, limits: DpopStreamLimits,
        resolve: R, observe: O,
    ) -> Result<DpopTaskWaitOutcome, DpopTaskWatchError>
    where
        R: FnMut(TaskInputRequests) -> F,
        F: Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
        O: FnMut(&Task) -> Result<(), ManagedTaskDriverError>,
    {
        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            return Err(DpopHttpError::Cancelled.into());
        }
        let timeout = self.policy.timeout.min(limits.core.timeout()).min(policy.input.timeout);
        let bounds = WaitBounds::new(cx, timeout, credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let input = InputDriver::new(policy.input, &metadata, resolve, observe)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        self.watch_task_using(
            cx, cancellation, credential, metadata, task, id_prefix,
            policy.watch, limits, bounds, (0, 0), Some(input),
        ).await
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "native-tls-roots"))]
mod reconnect_tls;

#[cfg(test)]
mod reconnect_admission_tests {
    use super::*;

    #[test]
    fn creating_ids_are_checked_against_every_configured_successor_before_creation() {
        let ordinary = DpopTaskWatchDriverPolicy::new(8, 2, 16, 4096, Duration::from_secs(60)).unwrap();
        let reconnecting = ordinary.with_reconnects(64, Duration::from_millis(1)).unwrap();
        let unrelated = RequestId::String("creating-call".to_owned());
        for index in [1, 2, 63, 64] {
            for suffix in ["", ".discover"] {
                let reserved = RequestId::String(format!("watch.listen.{index}{suffix}"));
                assert!(ordinary.admit_creation_ids("watch", [&unrelated, &reserved]).is_ok());
                for ids in [[&reserved, &unrelated], [&unrelated, &reserved]] {
                    assert!(matches!(reconnecting.admit_creation_ids("watch", ids),
                        Err(DpopTaskWatchError::Driver(ManagedTaskDriverError::RepeatedRequestId))));
                }
                assert!(reconnecting.admit_creation_ids("other", [&unrelated, &reserved]).is_ok());
            }
        }
        let outside = RequestId::String("watch.listen.65".to_owned());
        assert!(reconnecting.admit_creation_ids("watch", [&unrelated, &outside]).is_ok());
        for reserved in ["watch.listen", "watch.listen.discover", "watch.0.get", "watch.input.0.update"] {
            let reserved = RequestId::String(reserved.to_owned());
            assert!(reconnecting.admit_creation_ids("watch", [&unrelated, &reserved]).is_err());
        }
    }

    #[test]
    fn reconnect_configuration_preserves_driver_limits_and_composes_with_polling() {
        let original = DpopTaskWatchDriverPolicy::new(9, 3, 16, 4096, Duration::from_secs(27)).unwrap();
        let selected = original.with_reconnects(2, Duration::from_millis(7)).unwrap()
            .with_polling_fallback(4, Duration::from_millis(11)).unwrap();
        assert_eq!(selected.watch.maximum_snapshots, original.watch.maximum_snapshots);
        assert_eq!(selected.input.maximum_updates, original.input.maximum_updates);
        assert_eq!(selected.input.maximum_input_keys, original.input.maximum_input_keys);
        assert_eq!(selected.input.maximum_state_bytes, original.input.maximum_state_bytes);
        assert_eq!(selected.timeout(), original.timeout());
        assert_eq!(selected.watch.reconnect.unwrap().maximum_reconnects, 2);
        assert_eq!(selected.watch.fallback.unwrap().maximum_polls, 4);
        assert!(original.watch.reconnect.is_none());
        assert!(original.with_reconnects(0, Duration::from_millis(1)).is_err());
        assert!(original.with_reconnects(1, Duration::ZERO).is_err());
    }
}
