//! Bounded, request-owned fan-out without spawning tasks or creating a runtime.

use std::future::{Future, poll_fn};
use std::iter::Enumerate;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::vec::IntoIter;

use asupersync::time::Sleep;
use asupersync::{Cx, Time};

use super::ambient_capability_ceiling;
use crate::combinator::BoxFuture;
use crate::context::{ResourceReadResult, ToolCallResult};
use crate::{McpContext, McpError, McpResult};

const MAX_BATCH_OPERATIONS: usize = 4_096;
const MAX_BATCH_CONCURRENCY: usize = 64;
const LIVENESS_TICK_NANOS: u64 = 10_000_000;

fn admit_limits(concurrency: usize, count: usize) -> McpResult<()> {
    if !(1..=MAX_BATCH_CONCURRENCY).contains(&concurrency) || count > MAX_BATCH_OPERATIONS {
        return Err(McpError::invalid_params(
            "A bounded batch requires 1..=64 concurrent operations and at most 4096 inputs",
        ));
    }
    Ok(())
}

fn live(ctx: &McpContext) -> McpResult<()> {
    ctx.ensure_live().map_err(|_| McpError::request_cancelled())
}

fn allocation_error() -> McpError {
    McpError::internal_error("Bounded batch storage could not be reserved")
}

#[derive(Default)]
struct BatchWake {
    task: Mutex<Option<Waker>>,
}

impl BatchWake {
    fn register(&self, task: &Waker) {
        let mut current = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current.as_ref().is_none_or(|old| !old.will_wake(task)) {
            *current = Some(task.clone());
        }
    }

    fn notify(&self) {
        let task = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        // Never run an arbitrary waker with the registration lock held.
        if let Some(task) = task {
            task.wake();
        }
    }

    fn disarm(&self) {
        self.task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

struct ChildWake {
    ready: AtomicBool,
    active: AtomicBool,
    parent: Arc<BatchWake>,
}

impl Wake for ChildWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.active.load(Ordering::Acquire) && !self.ready.swap(true, Ordering::AcqRel) {
            self.parent.notify();
        }
    }
}

struct Slot<'a, T> {
    index: usize,
    future: BoxFuture<'a, McpResult<T>>,
    wake: Arc<ChildWake>,
}

impl<T> Drop for Slot<'_, T> {
    fn drop(&mut self) {
        // Retire readiness before the future's destructor can invoke its waker.
        self.wake.active.store(false, Ordering::Release);
    }
}

struct Batch<'a, T> {
    queued: Enumerate<IntoIter<BoxFuture<'a, McpResult<T>>>>,
    active: Vec<Option<Slot<'a, T>>>,
    results: Vec<Option<T>>,
    completed: usize,
    wake: Arc<BatchWake>,
}

impl<'a, T> Batch<'a, T> {
    fn new(concurrency: usize, futures: Vec<BoxFuture<'a, McpResult<T>>>) -> McpResult<Self> {
        let count = futures.len();
        let mut results = Vec::new();
        results
            .try_reserve_exact(count)
            .map_err(|_| allocation_error())?;
        results.resize_with(count, || None);
        let slots = concurrency.min(count);
        let mut active = Vec::new();
        active
            .try_reserve_exact(slots)
            .map_err(|_| allocation_error())?;
        active.resize_with(slots, || None);
        let mut batch = Self {
            queued: futures.into_iter().enumerate(),
            active,
            results,
            completed: 0,
            wake: Arc::new(BatchWake::default()),
        };
        batch.refill();
        Ok(batch)
    }

    fn refill(&mut self) -> bool {
        let mut refilled = false;
        for slot in &mut self.active {
            if slot.is_none() {
                let Some((index, future)) = self.queued.next() else {
                    break;
                };
                *slot = Some(Slot {
                    index,
                    future,
                    wake: Arc::new(ChildWake {
                        ready: AtomicBool::new(true),
                        active: AtomicBool::new(true),
                        parent: Arc::clone(&self.wake),
                    }),
                });
                refilled = true;
            }
        }
        refilled
    }

    fn poll_round(&mut self, ctx: &McpContext) -> McpResult<Option<Vec<T>>> {
        for slot in &mut self.active {
            let Some(current) = slot.as_mut() else {
                continue;
            };
            // Maintenance and sibling wakes never spend this child's poll quota.
            // Clear before polling so a wake inside poll is retained for next turn.
            if !current.wake.ready.swap(false, Ordering::AcqRel) {
                continue;
            }
            ctx.checkpoint()
                .map_err(|_| McpError::request_cancelled())?;
            let waker = Waker::from(Arc::clone(&current.wake));
            let result = current
                .future
                .as_mut()
                .poll(&mut Context::from_waker(&waker));
            // Liveness, not another debit: the last admitted unit may complete.
            live(ctx)?;
            if let Poll::Ready(result) = result {
                self.results[current.index] = Some(result?);
                self.completed += 1;
                *slot = None;
            }
        }
        if self.completed == self.results.len() {
            let mut output = Vec::new();
            output
                .try_reserve_exact(self.results.len())
                .map_err(|_| allocation_error())?;
            for result in &mut self.results {
                output.push(result.take().expect("every batch operation completed"));
            }
            return Ok(Some(output));
        }
        // Newly admitted slots are polled next turn, not recursively. Even a
        // queue of immediately-ready work has at most 64 polls in one turn.
        if self.refill() {
            self.wake.notify();
        }
        Ok(None)
    }

    fn retire(&mut self) {
        self.wake.disarm();
        self.active.clear();
        self.queued = Vec::new().into_iter().enumerate();
        self.results.clear();
    }
}

impl<T> Drop for Batch<'_, T> {
    fn drop(&mut self) {
        self.retire();
    }
}

#[derive(Default)]
struct LivenessClock {
    at: Option<Time>,
    timer: Option<Sleep>,
}

impl LivenessClock {
    fn poll(&mut self, ctx: &McpContext, task: &mut Context<'_>) {
        let now = ctx.cx().now();
        let tick = now.saturating_add_nanos(LIVENESS_TICK_NANOS);
        // A framework mask may defer an already-expired deadline. Do not keep
        // polling a completed timer or spin on that past deadline while masked.
        let next = ctx
            .budget()
            .deadline
            .filter(|deadline| *deadline > now)
            .map_or(tick, |deadline| tick.min(deadline));
        if self.at.is_none_or(|at| at <= now || next < at) {
            self.timer = Some(Sleep::new(next));
            self.at = Some(next);
        }
        if self
            .timer
            .as_mut()
            .is_some_and(|timer| Pin::new(timer).poll(task).is_ready())
        {
            self.timer = None;
            self.at = None;
            // The clock may advance during this poll. Re-arm on the next turn.
            task.waker().wake_by_ref();
        }
    }
}

impl McpContext {
    /// Runs a bounded batch concurrently, returning results in input order.
    ///
    /// At most `concurrency` futures have started but not completed. Queued
    /// futures are never polled early. The first observed error stops admission
    /// and drops all remaining futures and retained results without retrying.
    /// Successful completion preserves input order, not completion order.
    ///
    /// This observes the full request context, including its clone-shared poll
    /// budget, operation deadline, lease and request-local cancellation. Each
    /// application poll costs exactly one request checkpoint. A child is polled
    /// again only after its own wake; maintenance never consumes its allowance.
    /// Cancelling a batch never cancels the shared caller `Cx` or sibling requests.
    ///
    /// Request-local cancellation has its own wakeup. A caller-owned timer also
    /// checks liveness on 10ms ticks, observing runtime cancellation, silent lease
    /// closure and newly tightened deadlines without needing a child wakeup.
    /// Scheduling still depends on the caller driving its runtime. The caller
    /// must supply a timer driver and time capability for any nonempty batch.
    ///
    /// All futures are polled inline under the caller's runtime and the current
    /// ambient capability ceiling. No tasks, threads or runtimes are created.
    /// Dropping the batch drops queued and active futures and unregisters its
    /// timer/wakeups. It cannot undo committed effects or drain work that a
    /// supplied future spawned independently. Polls and destructors must not block.
    ///
    /// # Errors
    ///
    /// Refuses zero or more than 64 concurrency, more than 4096 inputs, missing
    /// timer authority, allocation failure, or an inactive request before work.
    /// Returns the exact first child error, or request cancellation on liveness
    /// or poll-budget refusal. Existing `join_all` wait-for-all semantics remain
    /// unchanged; this is the explicitly bounded, fail-fast operation.
    pub async fn try_join_all_bounded<'a, T: Send + 'a>(
        &'a self,
        concurrency: usize,
        futures: Vec<BoxFuture<'a, McpResult<T>>>,
    ) -> McpResult<Vec<T>> {
        admit_limits(concurrency, futures.len())?;
        live(self)?;
        if futures.is_empty() {
            return Ok(Vec::new());
        }
        if self.cx().timer_driver().is_none() {
            return Err(McpError::internal_error(
                "Bounded batch requires the caller's timer driver",
            ));
        }
        let mut batch = Batch::new(concurrency, futures)?;
        let mut cancelled = pin!(self.request_cancelled());
        let mut clock = LivenessClock::default();
        poll_fn(|task| {
            let ceiling = ambient_capability_ceiling();
            let _caller = Cx::set_current(Some(self.cx().clone()));
            let _restriction = Cx::push_restriction(ceiling);
            let result = (|| {
                live(self)?;
                if !Cx::current().is_some_and(|cx| cx.capabilities().time) {
                    return Err(McpError::internal_error(
                        "Bounded batch requires time capability",
                    ));
                }
                batch.wake.register(task.waker());
                if cancelled.as_mut().poll(task).is_ready() {
                    return Err(McpError::request_cancelled());
                }
                clock.poll(self, task);
                live(self)?;
                batch.poll_round(self)
            })();
            match result {
                Ok(None) => Poll::Pending,
                result => {
                    // Retire children while the admitted caller is still current.
                    batch.retire();
                    Poll::Ready(result.map(|output| output.expect("terminal batch result")))
                }
            }
        })
        .await
    }

    /// Calls several local tools with bounded request-owned concurrency.
    ///
    /// Every admitted call uses [`Self::call_tool`], retaining the originating
    /// request, exact tool name and arguments, shared budget and cross-component
    /// recursion limits. Queued calls do not enter the router until a slot is
    /// available. Results retain input order even when tools finish out of order.
    /// Duplicate calls are distinct operations: nothing is deduplicated or retried.
    ///
    /// An `Err(McpError)` stops the batch and drops pending and unstarted calls.
    /// A successful `ToolCallResult` with `is_error` set remains a tool result;
    /// it is not silently promoted to a protocol error or stripped of content.
    /// Earlier side effects are not rolled back when a later call fails.
    ///
    /// The limits, caller timer requirement, cancellation and cleanup contract
    /// of [`Self::try_join_all_bounded`] apply. This is handler composition, not
    /// a JSON-RPC wire batch and not a substitute for router authorization.
    pub async fn call_tools_bounded(
        &self,
        concurrency: usize,
        calls: Vec<(String, serde_json::Value)>,
    ) -> McpResult<Vec<ToolCallResult>> {
        admit_limits(concurrency, calls.len())?;
        live(self)?;
        let mut futures: Vec<BoxFuture<'_, McpResult<ToolCallResult>>> = Vec::new();
        futures
            .try_reserve_exact(calls.len())
            .map_err(|_| allocation_error())?;
        for (name, arguments) in calls {
            futures.push(Box::pin(
                async move { self.call_tool(&name, arguments).await },
            ));
        }
        self.try_join_all_bounded(concurrency, futures).await
    }

    /// Reads several resources with bounded request-owned concurrency.
    ///
    /// Each admitted read uses [`Self::read_resource`], preserving the exact URI,
    /// router policy, originating request and cross-component recursion depth.
    /// No URI rewriting or deduplication occurs. Results retain input order.
    /// The first error stops admission and drops active and queued reads; partial
    /// results are not returned as a successful catalog or silently retried.
    ///
    /// The limits, caller timer requirement, cancellation and cleanup contract
    /// of [`Self::try_join_all_bounded`] apply. Resource providers must still use
    /// nonblocking futures and retain ownership of any work they spawn elsewhere.
    pub async fn read_resources_bounded(
        &self,
        concurrency: usize,
        uris: Vec<String>,
    ) -> McpResult<Vec<ResourceReadResult>> {
        admit_limits(concurrency, uris.len())?;
        live(self)?;
        let mut futures: Vec<BoxFuture<'_, McpResult<ResourceReadResult>>> = Vec::new();
        futures
            .try_reserve_exact(uris.len())
            .map_err(|_| allocation_error())?;
        for uri in uris {
            futures.push(Box::pin(async move { self.read_resource(&uri).await }));
        }
        self.try_join_all_bounded(concurrency, futures).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::Budget;
    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use crate::McpErrorCode;
    use crate::context::{
        MAX_RESOURCE_READ_DEPTH, MAX_TOOL_CALL_DEPTH, ResourceReader, ToolCaller,
    };
    use serde_json::{Value, json};

    fn environment() -> (Runtime, Arc<VirtualClock>, TimerDriverHandle, McpContext) {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let ctx = McpContext::new(runtime.request_cx_with_budget(Budget::INFINITE), 7);
        (runtime, clock, timer, ctx)
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

    #[derive(Default)]
    struct Observed {
        ready: AtomicBool,
        polls: AtomicUsize,
        drops: AtomicUsize,
        waker: Mutex<Option<Waker>>,
    }

    impl Observed {
        fn finish(&self) {
            self.ready.store(true, Ordering::SeqCst);
            let waker = self.waker.lock().unwrap().clone();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    struct Probe {
        index: usize,
        failure: bool,
        observed: Arc<Observed>,
    }

    impl Future for Probe {
        type Output = McpResult<usize>;
        fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
            self.observed.polls.fetch_add(1, Ordering::SeqCst);
            *self.observed.waker.lock().unwrap() = Some(task.waker().clone());
            if !self.observed.ready.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            Poll::Ready(if self.failure {
                Err(McpError::invalid_params("planted batch failure"))
            } else {
                Ok(self.index)
            })
        }
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            self.observed.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    type Probes = (
        Vec<Arc<Observed>>,
        Vec<BoxFuture<'static, McpResult<usize>>>,
    );

    fn probes(count: usize, ready: bool, failure: Option<usize>) -> Probes {
        let observed: Vec<_> = (0..count).map(|_| Arc::new(Observed::default())).collect();
        let futures = observed
            .iter()
            .enumerate()
            .map(|(index, observed)| {
                observed.ready.store(ready, Ordering::SeqCst);
                Box::pin(Probe {
                    index,
                    failure: failure == Some(index),
                    observed: Arc::clone(observed),
                }) as BoxFuture<'static, McpResult<usize>>
            })
            .collect();
        (observed, futures)
    }

    fn poll<T>(future: Pin<&mut impl Future<Output = T>>, waker: &Waker) -> Poll<T> {
        future.poll(&mut Context::from_waker(waker))
    }

    fn completed<T>(result: Poll<McpResult<T>>) -> McpResult<T> {
        match result {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("batch stayed pending"),
        }
    }

    fn counts(observed: &[Arc<Observed>]) -> Vec<usize> {
        observed
            .iter()
            .map(|entry| entry.polls.load(Ordering::SeqCst))
            .collect()
    }

    fn all_dropped(observed: &[Arc<Observed>]) {
        assert!(
            observed
                .iter()
                .all(|entry| entry.drops.load(Ordering::SeqCst) == 1)
        );
    }

    #[test]
    fn bounded_batch_starts_only_available_slots_and_preserves_input_order() {
        let (runtime, _, _, ctx) = environment();
        let (observed, futures) = probes(5, false, None);
        let mut batch = Box::pin(ctx.try_join_all_bounded(2, futures));
        assert!(poll(batch.as_mut(), Waker::noop()).is_pending());
        assert_eq!(counts(&observed), vec![1, 1, 0, 0, 0]);
        for index in [1, 2, 3, 4] {
            observed[index].finish();
            assert!(poll(batch.as_mut(), Waker::noop()).is_pending());
            assert!(poll(batch.as_mut(), Waker::noop()).is_pending());
            assert_eq!(
                observed[0].polls.load(Ordering::SeqCst),
                1,
                "a sibling completion must not repoll silent work"
            );
        }
        observed[0].finish();
        assert_eq!(
            completed(poll(batch.as_mut(), Waker::noop())).unwrap(),
            vec![0, 1, 2, 3, 4]
        );
        assert_eq!(counts(&observed), vec![2; 5]);
        all_dropped(&observed);
        drop(batch);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn bounded_batch_failure_drops_active_and_queued_work_without_poisoning_caller() {
        for failure in [None, Some(1)] {
            let (runtime, _, timer, ctx) = environment();
            let (observed, futures) = probes(4, true, failure);
            let mut batch = Box::pin(ctx.try_join_all_bounded(2, futures));
            let result = poll(batch.as_mut(), Waker::noop());
            if failure.is_some() {
                let error = completed(result).unwrap_err();
                assert_eq!(error.message, "planted batch failure");
                assert_eq!(counts(&observed), vec![1, 1, 0, 0]);
            } else {
                assert!(result.is_pending());
                assert_eq!(counts(&observed), vec![1, 1, 0, 0]);
                assert_eq!(
                    completed(poll(batch.as_mut(), Waker::noop())).unwrap(),
                    vec![0, 1, 2, 3]
                );
            }
            all_dropped(&observed);
            assert_eq!(timer.pending_count(), 0);
            assert!(!ctx.cx().is_cancel_requested());
            drop(batch);
            let (_, futures) = probes(1, true, None);
            let mut sibling = Box::pin(ctx.try_join_all_bounded(1, futures));
            assert_eq!(
                completed(poll(sibling.as_mut(), Waker::noop())).unwrap(),
                vec![0]
            );
            drop(sibling);
            drop(ctx);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn bounded_batch_request_cancellation_wakes_silent_work_and_never_starts_queue() {
        let (runtime, _, timer, ctx) = environment();
        let (observed, futures) = probes(3, false, None);
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut batch = Box::pin(ctx.try_join_all_bounded(1, futures));
        assert!(poll(batch.as_mut(), &waker).is_pending());
        let before = wakes.0.load(Ordering::SeqCst);
        ctx.request_cancellation().cancel();
        assert!(
            wakes.0.load(Ordering::SeqCst) > before,
            "cancellation must wake without a clock tick"
        );
        assert_eq!(
            completed(poll(batch.as_mut(), &waker)).unwrap_err().code,
            McpErrorCode::RequestCancelled
        );
        assert_eq!(counts(&observed), vec![1, 0, 0]);
        all_dropped(&observed);
        assert_eq!(timer.pending_count(), 0);
        assert!(!ctx.cx().is_cancel_requested());
        drop(batch);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn bounded_batch_maintenance_does_not_spend_application_poll_budget() {
        let (runtime, clock, timer, ctx) = environment();
        let mut ceiling = Budget::INFINITE;
        ceiling.poll_quota = 2;
        let ctx = ctx.with_budget_ceiling(ceiling);
        let (observed, futures) = probes(1, false, None);
        let mut batch = Box::pin(ctx.try_join_all_bounded(1, futures));
        assert!(poll(batch.as_mut(), Waker::noop()).is_pending());
        for _ in 0..4 {
            clock.advance(LIVENESS_TICK_NANOS);
            assert!(timer.process_timers() > 0);
            assert!(poll(batch.as_mut(), Waker::noop()).is_pending());
            assert_eq!(ctx.budget().poll_quota, 1);
            assert_eq!(counts(&observed), vec![1]);
        }
        observed[0].finish();
        assert_eq!(
            completed(poll(batch.as_mut(), Waker::noop())).unwrap(),
            vec![0]
        );
        assert_eq!(
            ctx.budget().poll_quota,
            0,
            "the final admitted unit can complete"
        );
        assert!(ctx.ensure_live().is_ok());
        drop(batch);
        let (later, futures) = probes(1, true, None);
        let mut batch = Box::pin(ctx.try_join_all_bounded(1, futures));
        assert_eq!(
            completed(poll(batch.as_mut(), Waker::noop()))
                .unwrap_err()
                .code,
            McpErrorCode::RequestCancelled
        );
        assert_eq!(counts(&later), vec![0]);
        assert!(!ctx.cx().is_cancel_requested());
        drop(batch);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn bounded_batch_silent_liveness_changes_retire_work_on_the_callers_clock() {
        for cause in 0..4 {
            let (runtime, clock, timer, ctx) = environment();
            let (ctx, lease) = ctx.begin_request_scope().unwrap();
            let ctx = if cause == 0 {
                ctx.with_operation_deadline(Some(Time::from_nanos(3_000_000)))
            } else {
                ctx
            };
            let mut lease = Some(lease);
            let (observed, futures) = probes(2, false, None);
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut batch = Box::pin(ctx.try_join_all_bounded(1, futures));
            assert!(poll(batch.as_mut(), &waker).is_pending());
            match cause {
                0 => {}
                1 => {
                    let _tightened = ctx.clone().with_budget_ceiling(
                        Budget::INFINITE.with_deadline(Time::from_nanos(3_000_000)),
                    );
                }
                2 => {
                    drop(lease.take());
                }
                _ => ctx.cx().set_cancel_requested(true),
            }
            let before = wakes.0.load(Ordering::SeqCst);
            clock.advance(LIVENESS_TICK_NANOS);
            assert!(timer.process_timers() > 0);
            assert!(wakes.0.load(Ordering::SeqCst) > before);
            assert_eq!(
                completed(poll(batch.as_mut(), &waker)).unwrap_err().code,
                McpErrorCode::RequestCancelled
            );
            assert_eq!(counts(&observed), vec![1, 0]);
            all_dropped(&observed);
            assert_eq!(timer.pending_count(), 0);
            assert_eq!(ctx.cx().is_cancel_requested(), cause == 3);
            drop(batch);
            drop(lease);
            drop(ctx);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn bounded_batch_drop_retires_timer_cancellation_and_escaped_child_wakers() {
        let (runtime, _, timer, ctx) = environment();
        let (observed, futures) = probes(2, false, None);
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut batch = Box::pin(ctx.try_join_all_bounded(1, futures));
        assert!(poll(batch.as_mut(), &waker).is_pending());
        let escaped = observed[0].waker.lock().unwrap().clone().unwrap();
        drop(batch);
        all_dropped(&observed);
        assert_eq!(timer.pending_count(), 0);
        let before = wakes.0.load(Ordering::SeqCst);
        escaped.wake();
        ctx.request_cancellation().cancel();
        assert_eq!(wakes.0.load(Ordering::SeqCst), before);
        assert_eq!(Arc::strong_count(&wakes), 2);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn bounded_batch_mid_poll_cancellation_prevents_later_admission() {
        let (runtime, _, _, ctx) = environment();
        let cancel = ctx.request_cancellation();
        let started = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&started);
        let futures: Vec<BoxFuture<'_, McpResult<usize>>> = vec![
            Box::pin(async move {
                cancel.cancel();
                Ok(1)
            }),
            Box::pin(async move {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(2)
            }),
        ];
        let mut batch = Box::pin(ctx.try_join_all_bounded(2, futures));
        assert_eq!(
            completed(poll(batch.as_mut(), Waker::noop()))
                .unwrap_err()
                .code,
            McpErrorCode::RequestCancelled
        );
        assert_eq!(started.load(Ordering::SeqCst), 0);
        assert!(!ctx.cx().is_cancel_requested());
        drop(batch);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn bounded_batch_rechecks_effect_ceiling_and_preserves_caller_identity() {
        use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
        let (runtime, _, _, ctx) = environment();
        let foreign = Cx::for_testing();
        let _foreign = Cx::set_current(Some(foreign.clone()));
        let expected_task = ctx.cx().task_id();
        let expected_io = Arc::new(AtomicBool::new(true));
        let observed_io = Arc::clone(&expected_io);
        let observed = Arc::new(Observed::default());
        let child = Arc::clone(&observed);
        let future: BoxFuture<'_, McpResult<usize>> = Box::pin(poll_fn(move |task| {
            let active = Cx::current().unwrap();
            assert_eq!(active.task_id(), expected_task);
            assert_eq!(active.capabilities().io, observed_io.load(Ordering::SeqCst));
            *child.waker.lock().unwrap() = Some(task.waker().clone());
            if child.ready.load(Ordering::SeqCst) {
                Poll::Ready(Ok(42))
            } else {
                Poll::Pending
            }
        }));
        let mut batch = Box::pin(ctx.try_join_all_bounded(1, vec![future]));
        assert!(poll(batch.as_mut(), Waker::noop()).is_pending());
        expected_io.store(false, Ordering::SeqCst);
        observed.finish();
        {
            let _restriction = Cx::push_restriction(CapSet::<true, true, true, false, true>::MASK);
            assert_eq!(
                completed(poll(batch.as_mut(), Waker::noop())).unwrap(),
                vec![42]
            );
            assert!(!Cx::current().unwrap().capabilities().io);
        }
        assert!(Cx::current().unwrap().capabilities().io);
        drop(batch);
        let (observed, futures) = probes(1, true, None);
        let mut batch = Box::pin(ctx.try_join_all_bounded(1, futures));
        {
            let _restriction = Cx::push_restriction(CapMask::none());
            assert!(completed(poll(batch.as_mut(), Waker::noop())).is_err());
        }
        assert_eq!(counts(&observed), vec![0]);
        assert!(!foreign.is_cancel_requested());
        assert!(!ctx.cx().is_cancel_requested());
        drop(batch);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn bounded_batch_rejects_invalid_limits_and_driverless_work_without_polling() {
        for (concurrency, count) in [(0, 1), (65, 1), (1, 4097), (1, 1)] {
            let ctx = McpContext::new(Cx::for_testing(), 7);
            let (observed, futures) = probes(count, true, None);
            let mut batch = Box::pin(ctx.try_join_all_bounded(concurrency, futures));
            assert!(completed(poll(batch.as_mut(), Waker::noop())).is_err());
            assert!(counts(&observed).iter().all(|polls| *polls == 0));
            all_dropped(&observed);
        }
        let ctx = McpContext::new(Cx::for_testing(), 7);
        let mut empty = Box::pin(ctx.try_join_all_bounded::<usize>(1, Vec::new()));
        assert!(
            completed(poll(empty.as_mut(), Waker::noop()))
                .unwrap()
                .is_empty()
        );
    }

    type Visit = (&'static str, String, Value, u32);

    #[derive(Default)]
    struct RoutedProvider {
        visits: Mutex<Vec<Visit>>,
        released: Mutex<HashSet<String>>,
        waiters: Mutex<HashMap<String, Waker>>,
        drops: AtomicUsize,
    }

    struct RoutedDrop<'a>(&'a AtomicUsize);

    impl Drop for RoutedDrop<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl RoutedProvider {
        fn record(
            &self,
            ctx: &McpContext,
            kind: &'static str,
            name: &str,
            args: Value,
            depth: u32,
        ) {
            assert_eq!(ctx.request_id(), 7);
            assert_eq!(Cx::current().unwrap().task_id(), ctx.cx().task_id());
            self.visits
                .lock()
                .unwrap()
                .push((kind, name.to_owned(), args, depth));
        }

        async fn wait(&self, name: &str) {
            if !name.starts_with("wait:") {
                return;
            }
            poll_fn(|task| {
                self.waiters
                    .lock()
                    .unwrap()
                    .insert(name.to_owned(), task.waker().clone());
                if self.released.lock().unwrap().contains(name) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }

        fn release(&self, name: &str) {
            self.released.lock().unwrap().insert(name.to_owned());
            let waiter = self.waiters.lock().unwrap().get(name).cloned();
            if let Some(waiter) = waiter {
                waiter.wake();
            }
        }
    }

    impl ToolCaller for RoutedProvider {
        fn call_tool<'a>(
            &'a self,
            context: &'a McpContext,
            name: &'a str,
            args: Value,
            depth: u32,
        ) -> BoxFuture<'a, McpResult<ToolCallResult>> {
            Box::pin(async move {
                self.record(context, "tool", name, args, depth);
                let _drop = RoutedDrop(&self.drops);
                if name == "fail" {
                    return Err(McpError::invalid_params("routed failure"));
                }
                if name == "cancel" {
                    context.request_cancellation().cancel();
                }
                self.wait(name).await;
                Ok(if name == "tool-error" {
                    ToolCallResult::error("tool-level failure")
                } else {
                    ToolCallResult::text(name)
                })
            })
        }
    }

    impl ResourceReader for RoutedProvider {
        fn read_resource<'a>(
            &'a self,
            context: &'a McpContext,
            uri: &'a str,
            depth: u32,
        ) -> BoxFuture<'a, McpResult<ResourceReadResult>> {
            Box::pin(async move {
                self.record(context, "resource", uri, Value::Null, depth);
                let _drop = RoutedDrop(&self.drops);
                if uri == "fail" {
                    return Err(McpError::invalid_params("routed failure"));
                }
                if uri == "cancel" {
                    context.request_cancellation().cancel();
                }
                self.wait(uri).await;
                Ok(ResourceReadResult::text(uri, uri))
            })
        }
    }

    #[derive(Clone, Copy)]
    enum Composition {
        Tools,
        Resources,
    }

    async fn compose(
        kind: Composition,
        ctx: &McpContext,
        concurrency: usize,
        names: &[&str],
    ) -> McpResult<Vec<String>> {
        match kind {
            Composition::Tools => ctx
                .call_tools_bounded(
                    concurrency,
                    names
                        .iter()
                        .map(|name| ((*name).to_owned(), json!({})))
                        .collect(),
                )
                .await
                .map(|results| {
                    results
                        .iter()
                        .map(|result| result.first_text().unwrap().to_owned())
                        .collect()
                }),
            Composition::Resources => ctx
                .read_resources_bounded(
                    concurrency,
                    names.iter().map(|name| (*name).to_owned()).collect(),
                )
                .await
                .map(|results| {
                    results
                        .iter()
                        .map(|result| result.first_text().unwrap().to_owned())
                        .collect()
                }),
        }
    }

    fn finish_ready<T>(mut future: Pin<&mut impl Future<Output = McpResult<T>>>) -> McpResult<T> {
        for _ in 0..32 {
            if let Poll::Ready(result) = poll(future.as_mut(), Waker::noop()) {
                return result;
            }
        }
        panic!("ready routed batch did not finish within its test poll ceiling");
    }

    #[test]
    fn bounded_tool_calls_route_exact_arguments_and_limit_started_handlers() {
        let (runtime, _, timer, ctx) = environment();
        let provider = Arc::new(RoutedProvider::default());
        let ctx = ctx.with_tool_caller(provider.clone());
        let calls = ["wait:a", "wait:b", "wait:c", "wait:d"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                (
                    name.to_owned(),
                    json!({"value":index,"nested":{"exact":true}}),
                )
            })
            .collect();
        let mut batch = Box::pin(ctx.call_tools_bounded(2, calls));
        assert!(poll(batch.as_mut(), Waker::noop()).is_pending());
        assert_eq!(provider.visits.lock().unwrap().len(), 2);
        for name in ["wait:b", "wait:c", "wait:d"] {
            provider.release(name);
            assert!(poll(batch.as_mut(), Waker::noop()).is_pending());
            assert!(poll(batch.as_mut(), Waker::noop()).is_pending());
            let started = provider.visits.lock().unwrap().len();
            let dropped = provider.drops.load(Ordering::SeqCst);
            assert!(started - dropped <= 2);
        }
        provider.release("wait:a");
        let results = completed(poll(batch.as_mut(), Waker::noop())).unwrap();
        assert_eq!(
            results
                .iter()
                .map(|result| result.first_text().unwrap())
                .collect::<Vec<_>>(),
            vec!["wait:a", "wait:b", "wait:c", "wait:d"]
        );
        for (index, visit) in provider.visits.lock().unwrap().iter().enumerate() {
            assert_eq!(visit.0, "tool");
            assert_eq!(visit.2, json!({"value":index,"nested":{"exact":true}}));
            assert_eq!(visit.3, 1);
        }
        assert_eq!(provider.drops.load(Ordering::SeqCst), 4);
        assert_eq!(timer.pending_count(), 0);
        drop(batch);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn bounded_resource_reads_preserve_uris_input_order_and_shared_depth() {
        let (runtime, _, _, ctx) = environment();
        let provider = Arc::new(RoutedProvider::default());
        let ctx = ctx
            .with_resource_reader(provider.clone())
            .with_tool_call_depth(4);
        let uris = [
            "file:///docs/a%2Fb",
            "resource://catalog?kind=two",
            "file:///docs/a%2Fb",
        ];
        let mut batch = Box::pin(compose(Composition::Resources, &ctx, 1, &uris));
        assert_eq!(finish_ready(batch.as_mut()).unwrap(), uris);
        assert_eq!(
            *provider.visits.lock().unwrap(),
            uris.into_iter()
                .map(|uri| ("resource", uri.to_owned(), Value::Null, 5))
                .collect::<Vec<_>>()
        );
        assert_eq!(provider.drops.load(Ordering::SeqCst), 3);
        drop(batch);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn bounded_tool_error_payload_is_not_a_batch_failure() {
        let (runtime, _, _, ctx) = environment();
        let provider = Arc::new(RoutedProvider::default());
        let ctx = ctx.with_tool_caller(provider.clone());
        let mut batch = Box::pin(ctx.call_tools_bounded(
            1,
            vec![
                ("tool-error".to_owned(), json!({})),
                ("next".to_owned(), json!({})),
            ],
        ));
        let results = finish_ready(batch.as_mut()).unwrap();
        assert!(results[0].is_error);
        assert_eq!(results[0].first_text(), Some("tool-level failure"));
        assert!(!results[1].is_error);
        assert_eq!(results[1].first_text(), Some("next"));
        assert_eq!(provider.visits.lock().unwrap().len(), 2);
        drop(batch);
        drop(ctx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn bounded_composition_cancellation_and_errors_stop_unstarted_handlers() {
        for kind in [Composition::Tools, Composition::Resources] {
            for first in ["cancel", "fail"] {
                let (runtime, _, timer, ctx) = environment();
                let provider = Arc::new(RoutedProvider::default());
                let ctx = ctx
                    .with_tool_caller(provider.clone())
                    .with_resource_reader(provider.clone());
                let names = [first, "must-not-run"];
                let mut batch = Box::pin(compose(kind, &ctx, 1, &names));
                let error = completed(poll(batch.as_mut(), Waker::noop())).unwrap_err();
                if first == "cancel" {
                    assert_eq!(error.code, McpErrorCode::RequestCancelled);
                } else {
                    assert_eq!(error.message, "routed failure");
                }
                assert_eq!(provider.visits.lock().unwrap().len(), 1);
                assert_eq!(provider.visits.lock().unwrap()[0].1, first);
                assert_eq!(provider.drops.load(Ordering::SeqCst), 1);
                assert_eq!(timer.pending_count(), 0);
                assert!(!ctx.cx().is_cancel_requested());
                drop(batch);
                drop(ctx);
                assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
            }
        }
    }

    #[test]
    fn bounded_composition_keeps_cross_component_recursion_checks() {
        for kind in [Composition::Tools, Composition::Resources] {
            for at_limit in [false, true] {
                let (runtime, _, _, ctx) = environment();
                let provider = Arc::new(RoutedProvider::default());
                let ctx = ctx
                    .with_tool_caller(provider.clone())
                    .with_resource_reader(provider.clone());
                let limit = match kind {
                    Composition::Tools => MAX_TOOL_CALL_DEPTH,
                    Composition::Resources => MAX_RESOURCE_READ_DEPTH,
                };
                let depth = if at_limit { limit } else { limit - 1 };
                // Tighten the OTHER component's depth; a batch must not reset
                // tool -> resource or resource -> tool recursion accounting.
                let ctx = match kind {
                    Composition::Tools => ctx.with_resource_read_depth(depth),
                    Composition::Resources => ctx.with_tool_call_depth(depth),
                };
                let mut batch = Box::pin(compose(kind, &ctx, 1, &["item"]));
                let result = completed(poll(batch.as_mut(), Waker::noop()));
                if at_limit {
                    assert!(result.is_err());
                    assert!(provider.visits.lock().unwrap().is_empty());
                } else {
                    assert_eq!(result.unwrap(), vec!["item"]);
                    assert_eq!(provider.visits.lock().unwrap()[0].3, limit);
                }
                assert!(!ctx.cx().is_cancel_requested());
                drop(batch);
                drop(ctx);
                assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
            }
        }
    }

    #[test]
    fn bounded_composition_drop_releases_active_handler_and_never_admits_queue() {
        for kind in [Composition::Tools, Composition::Resources] {
            let (runtime, _, timer, ctx) = environment();
            let provider = Arc::new(RoutedProvider::default());
            let ctx = ctx
                .with_tool_caller(provider.clone())
                .with_resource_reader(provider.clone());
            let mut batch = Box::pin(compose(kind, &ctx, 1, &["wait:first", "wait:second"]));
            assert!(poll(batch.as_mut(), Waker::noop()).is_pending());
            assert_eq!(provider.visits.lock().unwrap().len(), 1);
            drop(batch);
            assert_eq!(provider.drops.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
            provider.release("wait:first");
            assert_eq!(provider.visits.lock().unwrap().len(), 1);
            assert!(ctx.ensure_live().is_ok());
            drop(ctx);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn bounded_composition_invalid_bounds_and_precancel_refuse_without_routing() {
        for kind in [Composition::Tools, Composition::Resources] {
            for concurrency in [0, 65, 1] {
                let (runtime, _, _, ctx) = environment();
                let provider = Arc::new(RoutedProvider::default());
                let ctx = ctx
                    .with_tool_caller(provider.clone())
                    .with_resource_reader(provider.clone());
                if concurrency == 1 {
                    ctx.request_cancellation().cancel();
                }
                let mut batch = Box::pin(compose(kind, &ctx, concurrency, &["item"]));
                assert!(completed(poll(batch.as_mut(), Waker::noop())).is_err());
                assert!(provider.visits.lock().unwrap().is_empty());
                assert_eq!(provider.drops.load(Ordering::SeqCst), 0);
                assert!(!ctx.cx().is_cancel_requested());
                drop(batch);
                drop(ctx);
                assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
            }
        }
    }
}

mod selection;
