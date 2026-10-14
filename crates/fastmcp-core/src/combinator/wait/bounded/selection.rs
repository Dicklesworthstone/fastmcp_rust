//! Request-owned, concurrency-bounded first-success and quorum selection.
//!
//! Reuse the bounded batch's slots, cancellation-safe wake registrations and
//! liveness clock. Unlike an all-success join, branch errors do not terminate
//! selection while enough uncompleted inputs can still satisfy the goal.

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;

use asupersync::Cx;

use super::super::ambient_capability_ceiling;
use super::{Batch, LivenessClock, admit_limits, allocation_error, live};
use crate::combinator::{BoxFuture, QuorumResult};
use crate::{McpContext, McpError, McpResult};

struct Selection<'a, T> {
    work: Batch<'a, T>,
    required: usize,
    failures: usize,
    last_error: Option<McpError>,
}

struct Selected<T> {
    quorum: QuorumResult<T>,
    last_error: Option<McpError>,
}

impl<T> Selection<'_, T> {
    fn finish(&mut self) -> McpResult<Selected<T>> {
        let mut successes = Vec::new();
        successes
            .try_reserve_exact(self.work.completed)
            .map_err(|_| allocation_error())?;
        // Selection owns the prefix in observed completion order, rather than
        // the original input-index order used by Batch::poll_round. Each slot
        // is taken exactly once; the unused tail owns no values.
        for value in self.work.results.iter_mut().take(self.work.completed) {
            successes.push(value.take().expect("selected success remains owned"));
        }
        Ok(Selected {
            quorum: QuorumResult {
                successes,
                quorum_met: self.work.completed == self.required,
                failure_count: self.failures,
            },
            last_error: self.last_error.take(),
        })
    }

    fn poll_round(&mut self, ctx: &McpContext) -> McpResult<Option<Selected<T>>> {
        for index in 0..self.work.active.len() {
            let result = {
                let Some(slot) = self.work.active[index].as_mut() else {
                    continue;
                };
                if !slot
                    .wake
                    .ready
                    .swap(false, std::sync::atomic::Ordering::AcqRel)
                {
                    continue;
                }
                // A maintenance tick or a sibling wake cannot spend this
                // branch's allowance. Only an admitted application poll does.
                ctx.checkpoint()
                    .map_err(|_| McpError::request_cancelled())?;
                let waker = std::task::Waker::from(std::sync::Arc::clone(&slot.wake));
                let result = slot
                    .future
                    .as_mut()
                    .poll(&mut std::task::Context::from_waker(&waker));
                live(ctx)?;
                result
            };
            if let Poll::Ready(result) = result {
                self.work.active[index] = None;
                // A completed future's destructor may stop the request too.
                // Do not publish a winner or admit another branch afterward.
                live(ctx)?;
                match result {
                    Ok(value) => {
                        self.work.results[self.work.completed] = Some(value);
                        self.work.completed += 1;
                    }
                    Err(error) => {
                        self.failures += 1;
                        self.last_error = Some(error);
                    }
                }
                // Decide at this slot, before polling another ready loser or
                // refilling the queue. Count queued AND active inputs when
                // deciding impossibility; a silent branch need not finish.
                if self.work.completed == self.required
                    || self.failures > self.work.results.len() - self.required
                {
                    return self.finish().map(Some);
                }
            }
        }
        // Reuse the batch's bounded admission: replacements start next turn,
        // even when every supplied future returns immediately.
        if self.work.refill() {
            self.work.wake.notify();
        }
        Ok(None)
    }
}

async fn select<'a, T: Send + 'a>(
    ctx: &'a McpContext,
    concurrency: usize,
    required: usize,
    futures: Vec<BoxFuture<'a, McpResult<T>>>,
) -> McpResult<Selected<T>> {
    admit_limits(concurrency, futures.len())?;
    if required > futures.len() {
        return Err(McpError::invalid_params(
            "Bounded quorum requires more successes than supplied inputs",
        ));
    }
    live(ctx)?;
    if required == 0 {
        return Ok(Selected {
            quorum: QuorumResult {
                successes: Vec::new(),
                quorum_met: true,
                failure_count: 0,
            },
            last_error: None,
        });
    }
    if ctx.cx().timer_driver().is_none() {
        return Err(McpError::internal_error(
            "Bounded selection requires the caller's timer driver",
        ));
    }
    let mut selection = Selection {
        work: Batch::new(concurrency, futures)?,
        required,
        failures: 0,
        last_error: None,
    };
    let mut cancelled = pin!(ctx.request_cancelled());
    let mut clock = LivenessClock::default();
    poll_fn(|task| {
        let ceiling = ambient_capability_ceiling();
        let _caller = Cx::set_current(Some(ctx.cx().clone()));
        let _restriction = Cx::push_restriction(ceiling);
        let result = (|| {
            live(ctx)?;
            if !Cx::current().is_some_and(|cx| cx.capabilities().time) {
                return Err(McpError::internal_error(
                    "Bounded selection requires time capability",
                ));
            }
            selection.work.wake.register(task.waker());
            if cancelled.as_mut().poll(task).is_ready() {
                return Err(McpError::request_cancelled());
            }
            clock.poll(ctx, task);
            live(ctx)?;
            selection.poll_round(ctx)
        })();
        match result {
            Ok(None) => Poll::Pending,
            result => {
                // Retire active and queued futures before returning, under
                // the admitted caller. Do not cancel the shared Cx or pretend
                // that dropping a future rolls back its committed effects.
                selection.work.retire();
                Poll::Ready(result.and_then(|selected| {
                    live(ctx)?;
                    Ok(selected.expect("selection has a terminal decision"))
                }))
            }
        }
    })
    .await
}

impl McpContext {
    /// Waits for a bounded number of successful branches without starting all inputs.
    ///
    /// At most `concurrency` supplied futures have started but not completed.
    /// Returns immediately after `required` successes are observed, or as soon
    /// as too many branches have failed for the remaining inputs to meet that
    /// goal. An impossible quorum is `Ok(QuorumResult { quorum_met: false, .. })`;
    /// it retains successes already observed and the count of observed errors.
    /// It never waits for silent losers after impossibility is established.
    ///
    /// Successes follow observed completion order (slot order breaks ties),
    /// not input order. No later slot is polled after the decision. All active
    /// and queued losers are dropped before return. A branch error, including
    /// a branch-local cancellation error, counts as a failure; cancellation of
    /// THIS request instead returns `Err(RequestCancelled)`, never a partial
    /// successful result. Values and errors are not votes on their contents:
    /// the application remains responsible for validating agreement.
    ///
    /// This shares the request-owned bounds and lifetime contract of
    /// [`Self::try_join_all_bounded`]: 1..=64 concurrency, at most 4096 inputs,
    /// one request checkpoint per woken application poll, native request-local
    /// cancellation wakeups, and caller-clock liveness checks for leases,
    /// cancellation and tightened deadlines. A nonzero goal requires the
    /// caller's timer driver and time capability. A zero goal polls no input
    /// and needs no timer, but still validates bounds and request liveness.
    /// `required` may exceed `concurrency`, but must not exceed the input count.
    ///
    /// No worker, runtime, wire batch, retry or remote cancellation is created.
    /// Use this for explicitly independent alternatives or replicas: started
    /// work may already have committed effects which dropping cannot undo.
    /// Work spawned independently by a branch is not drained by this operation.
    pub async fn quorum_bounded<'a, T: Send + 'a>(
        &'a self,
        concurrency: usize,
        required: usize,
        futures: Vec<BoxFuture<'a, McpResult<T>>>,
    ) -> McpResult<QuorumResult<T>> {
        select(self, concurrency, required, futures)
            .await
            .map(|selected| selected.quorum)
    }

    /// Tries bounded concurrent alternatives and returns the first observed success.
    ///
    /// Branch errors free capacity for later inputs rather than stopping the
    /// operation. If every input fails, returns the exact last observed error,
    /// preserving its code, message and data. Empty input is invalid. Set
    /// `concurrency` to one for ordered fallback without speculative execution.
    /// A silent active branch still occupies a slot until completion, request
    /// cancellation or a request deadline; this never invents a per-branch timeout.
    ///
    /// The bounds, wake-driven polling, effect restrictions, caller-clock and
    /// request-local cancellation contract of [`Self::quorum_bounded`] apply.
    /// Losing and unstarted futures are dropped before the winner is returned.
    /// A successful tool payload with `is_error` set is still an `Ok` value;
    /// classify application-level failures explicitly in the supplied futures.
    pub async fn first_ok_bounded<'a, T: Send + 'a>(
        &'a self,
        concurrency: usize,
        futures: Vec<BoxFuture<'a, McpResult<T>>>,
    ) -> McpResult<T> {
        if futures.is_empty() {
            return Err(McpError::invalid_params(
                "Bounded first success requires at least one input",
            ));
        }
        let selected = select(self, concurrency, 1, futures).await?;
        if selected.quorum.quorum_met {
            Ok(selected
                .quorum
                .successes
                .into_iter()
                .next()
                .expect("one selected success"))
        } else {
            Err(selected
                .last_error
                .expect("every input failed before first-success refusal"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::task::{Context, Wake, Waker};
    use std::time::Duration;

    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use asupersync::{Budget, Time};
    use crate::McpErrorCode;

    fn environment() -> (Runtime, Arc<VirtualClock>, TimerDriverHandle, McpContext) {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let ctx = McpContext::new(runtime.request_cx_with_budget(Budget::INFINITE), 71);
        (runtime, clock, timer, ctx)
    }

    #[derive(Default)]
    struct Seen {
        ready: AtomicBool,
        polls: AtomicUsize,
        drops: AtomicUsize,
        waker: Mutex<Option<Waker>>,
    }

    impl Seen {
        fn finish(&self) {
            self.ready.store(true, Ordering::Release);
            let waker = self.waker.lock().unwrap().clone();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    struct Branch {
        index: usize,
        fails: bool,
        seen: Arc<Seen>,
    }

    impl Future for Branch {
        type Output = McpResult<usize>;
        fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
            self.seen.polls.fetch_add(1, Ordering::SeqCst);
            *self.seen.waker.lock().unwrap() = Some(task.waker().clone());
            if !self.seen.ready.load(Ordering::Acquire) {
                return Poll::Pending;
            }
            Poll::Ready(if self.fails {
                Err(McpError::with_data(
                    McpErrorCode::InvalidParams,
                    format!("branch {} refused", self.index),
                    serde_json::json!({"branch": self.index}),
                ))
            } else {
                Ok(self.index)
            })
        }
    }

    impl Drop for Branch {
        fn drop(&mut self) {
            self.seen.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    type Branches = (Vec<Arc<Seen>>, Vec<BoxFuture<'static, McpResult<usize>>>);

    fn branches(kinds: &[(bool, bool)]) -> Branches {
        let seen: Vec<_> = kinds.iter().map(|_| Arc::new(Seen::default())).collect();
        let futures = kinds
            .iter()
            .enumerate()
            .map(|(index, (ready, fails))| {
                seen[index].ready.store(*ready, Ordering::Release);
                Box::pin(Branch {
                    index,
                    fails: *fails,
                    seen: Arc::clone(&seen[index]),
                }) as BoxFuture<'static, McpResult<usize>>
            })
            .collect();
        (seen, futures)
    }

    fn counts(seen: &[Arc<Seen>]) -> Vec<usize> {
        seen.iter()
            .map(|seen| seen.polls.load(Ordering::SeqCst))
            .collect()
    }

    fn dropped(seen: &[Arc<Seen>]) {
        assert!(seen.iter().all(|seen| seen.drops.load(Ordering::SeqCst) == 1));
    }

    fn poll<F: Future + ?Sized>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(waker))
    }

    fn done<T>(value: Poll<McpResult<T>>) -> McpResult<T> {
        match value {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("selection did not reach its expected decision"),
        }
    }

    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn first_success_refills_failed_slots_without_repolling_silent_siblings() {
        let (runtime, _, timer, ctx) = environment();
        let (seen, futures) = branches(&[
            (true, true), (false, false), (true, false), (true, false),
        ]);
        let mut selection = Box::pin(ctx.first_ok_bounded(2, futures));
        assert!(poll(selection.as_mut(), Waker::noop()).is_pending());
        assert_eq!(counts(&seen), vec![1, 1, 0, 0]);
        assert_eq!(done(poll(selection.as_mut(), Waker::noop())).unwrap(), 2);
        assert_eq!(counts(&seen), vec![1, 1, 1, 0]);
        dropped(&seen);
        assert_eq!(timer.pending_count(), 0);
        assert!(ctx.ensure_live().is_ok());
        assert!(!ctx.cx().is_cancel_requested());
        drop(selection);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn bounded_quorum_retains_completion_order_and_can_exceed_concurrency() {
        let (runtime, _, timer, ctx) = environment();
        let (seen, futures) = branches(&[
            (false, false), (true, false), (true, true),
            (true, false), (true, false), (true, false),
        ]);
        let mut selection = Box::pin(ctx.quorum_bounded(2, 3, futures));
        for expected in [
            vec![1, 1, 0, 0, 0, 0],
            vec![1, 1, 1, 0, 0, 0],
            vec![1, 1, 1, 1, 0, 0],
        ] {
            assert!(poll(selection.as_mut(), Waker::noop()).is_pending());
            assert_eq!(counts(&seen), expected);
        }
        let result = done(poll(selection.as_mut(), Waker::noop())).unwrap();
        assert!(result.quorum_met);
        assert_eq!(result.successes, vec![1, 3, 4]);
        assert_eq!(result.failure_count, 1);
        assert_eq!(counts(&seen), vec![1, 1, 1, 1, 1, 0]);
        dropped(&seen);
        assert_eq!(timer.pending_count(), 0);
        drop(selection);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn impossible_quorum_does_not_wait_for_silent_work_or_poll_later_ready_losers() {
        let (runtime, _, timer, ctx) = environment();
        let (seen, futures) = branches(&[
            (false, false), (true, false), (true, true), (true, true), (true, false),
        ]);
        let mut selection = Box::pin(ctx.quorum_bounded(4, 4, futures));
        let result = done(poll(selection.as_mut(), Waker::noop())).unwrap();
        assert!(!result.quorum_met);
        assert_eq!(result.successes, vec![1]);
        assert_eq!(result.failure_count, 2);
        assert_eq!(counts(&seen), vec![1, 1, 1, 1, 0]);
        dropped(&seen);
        assert_eq!(timer.pending_count(), 0);
        assert!(ctx.ensure_live().is_ok());
        drop(selection);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn first_success_preserves_last_error_and_bounds_immediate_failures_per_turn() {
        let (runtime, _, timer, ctx) = environment();
        let (seen, futures) = branches(&vec![(true, true); 129]);
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut selection = Box::pin(ctx.first_ok_bounded(64, futures));
        for expected in [64, 128] {
            let before = wakes.0.load(Ordering::SeqCst);
            assert!(poll(selection.as_mut(), &waker).is_pending());
            assert_eq!(counts(&seen).iter().sum::<usize>(), expected);
            assert!(wakes.0.load(Ordering::SeqCst) > before);
        }
        let error = done(poll(selection.as_mut(), &waker)).unwrap_err();
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(error.message, "branch 128 refused");
        assert_eq!(error.data, Some(serde_json::json!({"branch":128})));
        assert!(counts(&seen).iter().all(|polls| *polls == 1));
        dropped(&seen);
        assert_eq!(timer.pending_count(), 0);
        drop(selection);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn zero_goal_and_invalid_bounds_do_not_poll_or_require_a_timer() {
        let ctx = McpContext::new(Cx::for_testing(), 71);
        let (seen, futures) = branches(&[(true, false), (true, true)]);
        let mut zero = Box::pin(ctx.quorum_bounded(1, 0, futures));
        let result = done(poll(zero.as_mut(), Waker::noop())).unwrap();
        assert!(result.quorum_met && result.successes.is_empty());
        assert_eq!(result.failure_count, 0);
        assert_eq!(counts(&seen), vec![0, 0]);
        dropped(&seen);
        drop(zero);
        for (concurrency, required, count) in [
            (0, 0, 1), (65, 1, 1), (1, 2, 1), (1, 0, 4097), (1, 1, 1),
        ] {
            let (seen, futures) = branches(&vec![(true, false); count]);
            let mut selection = Box::pin(ctx.quorum_bounded(concurrency, required, futures));
            assert!(done(poll(selection.as_mut(), Waker::noop())).is_err());
            assert!(counts(&seen).iter().all(|polls| *polls == 0));
            dropped(&seen);
        }
        let mut empty = Box::pin(ctx.first_ok_bounded::<usize>(1, Vec::new()));
        assert_eq!(
            done(poll(empty.as_mut(), Waker::noop())).unwrap_err().code,
            McpErrorCode::InvalidParams
        );
        drop(empty);
        ctx.request_cancellation().cancel();
        let mut zero = Box::pin(ctx.quorum_bounded::<usize>(1, 0, Vec::new()));
        assert_eq!(
            done(poll(zero.as_mut(), Waker::noop())).unwrap_err().code,
            McpErrorCode::RequestCancelled
        );
    }

    #[test]
    fn request_cancellation_wakes_selection_and_does_not_cancel_an_independent_sibling() {
        for first_success in [false, true] {
            let (runtime, _, timer, ctx) = environment();
            let sibling = McpContext::new(ctx.cx().clone(), 72);
            let (seen, futures) = branches(&[(false, false), (true, false)]);
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut selection: BoxFuture<'_, McpResult<()>> = if first_success {
                Box::pin(async { ctx.first_ok_bounded(1, futures).await.map(|_| ()) })
            } else {
                Box::pin(async { ctx.quorum_bounded(1, 1, futures).await.map(|_| ()) })
            };
            assert!(poll(selection.as_mut(), &waker).is_pending());
            let before = wakes.0.load(Ordering::SeqCst);
            ctx.request_cancellation().cancel();
            assert!(wakes.0.load(Ordering::SeqCst) > before);
            assert_eq!(
                done(poll(selection.as_mut(), &waker)).unwrap_err().code,
                McpErrorCode::RequestCancelled
            );
            assert_eq!(counts(&seen), vec![1, 0]);
            dropped(&seen);
            assert_eq!(timer.pending_count(), 0);
            assert!(!ctx.cx().is_cancel_requested());
            drop(selection);
            let (_, futures) = branches(&[(true, false)]);
            let mut other = Box::pin(sibling.first_ok_bounded(1, futures));
            assert_eq!(done(poll(other.as_mut(), Waker::noop())).unwrap(), 0);
            drop(other);
            drop((ctx, sibling));
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn selection_maintenance_preserves_poll_budget_and_returns_borrowed_values() {
        let (runtime, clock, timer, ctx) = environment();
        let mut budget = Budget::INFINITE;
        budget.poll_quota = 2;
        let ctx = ctx.with_budget_ceiling(budget);
        let value = String::from("borrowed winner");
        let seen = Arc::new(Seen::default());
        let observed = Arc::clone(&seen);
        let borrowed = value.as_str();
        let future: BoxFuture<'_, McpResult<&str>> = Box::pin(poll_fn(move |task| {
            observed.polls.fetch_add(1, Ordering::SeqCst);
            *observed.waker.lock().unwrap() = Some(task.waker().clone());
            if observed.ready.load(Ordering::Acquire) {
                Poll::Ready(Ok(borrowed))
            } else {
                Poll::Pending
            }
        }));
        let mut selection = Box::pin(ctx.first_ok_bounded(1, vec![future]));
        assert!(poll(selection.as_mut(), Waker::noop()).is_pending());
        for _ in 0..4 {
            clock.advance(super::super::LIVENESS_TICK_NANOS);
            assert!(timer.process_timers() > 0);
            assert!(poll(selection.as_mut(), Waker::noop()).is_pending());
            assert_eq!(ctx.budget().poll_quota, 1);
            assert_eq!(seen.polls.load(Ordering::SeqCst), 1);
        }
        seen.finish();
        assert_eq!(
            done(poll(selection.as_mut(), Waker::noop())).unwrap(),
            "borrowed winner"
        );
        assert_eq!(ctx.budget().poll_quota, 0);
        assert!(ctx.ensure_live().is_ok());
        assert_eq!(timer.pending_count(), 0);
        drop(selection);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn selection_observes_deadlines_lease_closure_and_runtime_cancellation_without_child_wakes() {
        for cause in 0..4 {
            let (runtime, clock, timer, ctx) = environment();
            let (ctx, lease) = ctx.begin_request_scope().unwrap();
            let ctx = if cause == 0 {
                ctx.with_operation_deadline(Some(Time::from_nanos(3_000_000)))
            } else {
                ctx
            };
            let mut lease = Some(lease);
            let (seen, futures) = branches(&[(false, false), (true, false)]);
            let mut selection = Box::pin(ctx.quorum_bounded(1, 1, futures));
            assert!(poll(selection.as_mut(), Waker::noop()).is_pending());
            match cause {
                0 => {}
                1 => {
                    let _ = ctx.clone().with_budget_ceiling(
                        Budget::INFINITE.with_deadline(Time::from_nanos(3_000_000)),
                    );
                }
                2 => {
                    drop(lease.take());
                }
                _ => ctx.cx().set_cancel_requested(true),
            }
            clock.advance(super::super::LIVENESS_TICK_NANOS);
            assert!(timer.process_timers() > 0);
            assert_eq!(
                done(poll(selection.as_mut(), Waker::noop())).unwrap_err().code,
                McpErrorCode::RequestCancelled
            );
            assert_eq!(counts(&seen), vec![1, 0]);
            dropped(&seen);
            assert_eq!(timer.pending_count(), 0);
            assert_eq!(ctx.cx().is_cancel_requested(), cause == 3);
            drop(selection);
            drop((lease, ctx));
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn selection_replaces_parent_wakers_and_abandonment_disarms_escaped_child_wakes() {
        let (runtime, _, timer, ctx) = environment();
        let (seen, futures) = branches(&[(false, false), (true, false)]);
        let old = Arc::new(Wakes::default());
        let new = Arc::new(Wakes::default());
        let old_waker = Waker::from(Arc::clone(&old));
        let new_waker = Waker::from(Arc::clone(&new));
        let mut selection = Box::pin(ctx.first_ok_bounded(1, futures));
        assert!(poll(selection.as_mut(), &old_waker).is_pending());
        assert!(poll(selection.as_mut(), &new_waker).is_pending());
        seen[0].finish();
        assert_eq!(old.0.load(Ordering::SeqCst), 0);
        assert!(new.0.load(Ordering::SeqCst) > 0);
        let escaped = seen[0].waker.lock().unwrap().clone().unwrap();
        drop(selection);
        dropped(&seen);
        assert_eq!(timer.pending_count(), 0);
        let before = new.0.load(Ordering::SeqCst);
        escaped.wake();
        ctx.request_cancellation().cancel();
        assert_eq!(new.0.load(Ordering::SeqCst), before);
        assert_eq!(counts(&seen), vec![1, 0]);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn selection_cancellation_during_a_ready_child_wins_before_next_branch() {
        for quorum in [false, true] {
            let (runtime, _, timer, ctx) = environment();
            let cancellation = ctx.request_cancellation();
            let (seen, mut futures) = branches(&[(true, false)]);
            futures.insert(0, Box::pin(async move {
                cancellation.cancel();
                Ok(99)
            }));
            let mut selection: BoxFuture<'_, McpResult<()>> = if quorum {
                Box::pin(async { ctx.quorum_bounded(2, 1, futures).await.map(|_| ()) })
            } else {
                Box::pin(async { ctx.first_ok_bounded(2, futures).await.map(|_| ()) })
            };
            assert_eq!(
                done(poll(selection.as_mut(), Waker::noop())).unwrap_err().code,
                McpErrorCode::RequestCancelled
            );
            assert_eq!(counts(&seen), vec![0]);
            dropped(&seen);
            assert_eq!(timer.pending_count(), 0);
            assert!(!ctx.cx().is_cancel_requested());
            drop(selection);
            drop(ctx);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn selection_refuses_lost_time_authority_before_polling_children_and_retires_timers() {
        use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
        for initial in [false, true] {
            let (runtime, _, timer, ctx) = environment();
            let (seen, futures) = branches(&[(false, false)]);
            let mut selection = Box::pin(ctx.first_ok_bounded(1, futures));
            if !initial {
                assert!(poll(selection.as_mut(), Waker::noop()).is_pending());
            }
            {
                let _caller = Cx::set_current(Some(ctx.cx().clone()));
                let _restriction = Cx::push_restriction(
                    CapSet::<true, false, true, true, true>::MASK,
                );
                assert!(done(poll(selection.as_mut(), Waker::noop())).is_err());
                assert!(!Cx::current().unwrap().capabilities().time);
            }
            assert_eq!(counts(&seen), vec![usize::from(!initial)]);
            dropped(&seen);
            assert_eq!(timer.pending_count(), 0);
            assert!(ctx.ensure_live().is_ok());
            drop(selection);
            drop(ctx);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }
}
