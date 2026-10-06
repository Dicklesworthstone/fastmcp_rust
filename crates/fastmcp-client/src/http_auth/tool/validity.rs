//! A caller-polled lifetime fence for schema-bound work, not a second runtime.
//!
//! Register invalidation before polling the owned operation, then recheck after
//! every poll. This closes the pending-renewal/read/resume window without
//! retrying a request, extending a deadline or cancelling the shared login.
//! Already-dispatched side effects cannot be recalled. Dropping a renewal that
//! may have consumed its refresh token retains the session's existing refusal
//! to reuse that uncertain lineage.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::cx::cap;
use asupersync::time::Sleep;
use fastmcp_core::McpRequestCancellation;

use super::{ManagedCoreError, ManagedToolError, ToolContract, check_tool_call};

// T deliberately includes the inner Result. Interaction-local answer refusals
// must retain their original type and challenge; invalidation is terminal and
// must not enter that correctable-input branch or restore the owned operation.
// Generic over the caller's capability set rather than demanding the full one.
// The body needs TIME for the caller deadline and nothing else, so a caller
// holding a narrower authority can still fence its own work here. The
// capability flows to the callback through `set_current_restricted` below, so
// widening it is a compile error rather than a review item.
pub(super) async fn await_validity<Caps, T>(
    cx: &Cx<Caps>,
    cancellation: &McpRequestCancellation,
    contract: &ToolContract,
    future: impl Future<Output = T>,
) -> Result<T, ManagedToolError>
where
    Caps: cap::HasTime + cap::CapSetRuntimeMask,
{
    let mut invalidated = std::pin::pin!(contract.invalidation.cancelled());
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    // The pinned asupersync 0.5 API has no public Cx::cancelled observer.
    // An unsent, retained oneshot gives us its cancellation-safe receive
    // registration without spawning work, polling a timer or inventing a Cx.
    // Keep the sender alive across the await: only the caller's checkpoint
    // refusal can complete this receive. Drop unregisters this waiter alone.
    let (_keep_open, mut context_receiver) = oneshot::channel::<()>();
    let mut context_cancelled = std::pin::pin!(context_receiver.recv(cx));
    // Capture one absolute caller deadline; repeated polls never replenish it.
    // The transport may impose an even earlier operation-specific deadline.
    let deadline = cx.budget().deadline;
    let mut deadline_timer = deadline.map(Sleep::new);
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        // Native timers and callbacks must use the supplied caller's authority,
        // not another task's ambient context. This guard ends before Pending.
        // `set_current_restricted`, not `set_current`: the latter publishes only
        // the caller's runtime mask and silently discards its type-level
        // capability set, so a narrowed caller's callback would observe the
        // wider ambient authority through `Cx::current()`. Intersecting both
        // layers is what makes the caller's bound actually bind.
        let _caller = cx.clone().set_current_restricted();
        check_tool_call(cx, cancellation, contract)?;
        if deadline.is_some_and(|deadline| cx.now() >= deadline) {
            return Poll::Ready(Err(ManagedCoreError::TimedOut.into()));
        }
        if let Some(timer) = deadline_timer.as_mut() {
            // Sleep resolves its driver on poll in asupersync 0.5. Never borrow
            // an unrelated ambient driver or silently omit a caller deadline.
            if cx.timer_driver().is_none() {
                return Poll::Ready(Err(ManagedCoreError::RuntimeUnavailable.into()));
            }
            if Pin::new(timer).poll(task).is_ready() {
                return Poll::Ready(Err(ManagedCoreError::TimedOut.into()));
            }
        }
        if invalidated.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(ManagedToolError::Invalidated));
        }
        if cancelled.as_mut().poll(task).is_ready()
            || context_cancelled.as_mut().poll(task).is_ready()
        {
            return Poll::Ready(Err(ManagedCoreError::Cancelled.into()));
        }
        let outcome = future.as_mut().poll(task);
        // Refuse even a simultaneously ready result. Owned response state is
        // dropped on this error; partially read work cannot become reusable.
        check_tool_call(cx, cancellation, contract)?;
        if deadline.is_some_and(|deadline| cx.now() >= deadline) {
            return Poll::Ready(Err(ManagedCoreError::TimedOut.into()));
        }
        outcome.map(Ok)
    })
    .await
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod context_cancellation_tests {
    use super::*;
    use asupersync::types::CancelKind;
    use fastmcp_protocol::FinalTool;
    use serde_json::json;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    fn contract() -> ToolContract {
        ToolContract::admit(FinalTool {
            name: "calculate".to_owned(),
            title: None,
            description: None,
            icons: None,
            input_schema: json!({"type": "object"}),
            output_schema: None,
            annotations: None,
            meta: None,
        })
        .unwrap()
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
    struct State {
        polls: AtomicUsize,
        dropped: AtomicBool,
    }

    struct Waiting(Arc<State>);

    impl Future for Waiting {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            self.0.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        }
    }

    impl Drop for Waiting {
        fn drop(&mut self) {
            self.0.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn caller_cancellation_wakes_and_drops_an_uncooperative_pending_operation() {
        let cx = Cx::for_testing();
        let contract = contract();
        let cancellation = McpRequestCancellation::new();
        let state = Arc::new(State::default());
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(await_validity(
            &cx,
            &cancellation,
            &contract,
            Waiting(state.clone()),
        ));
        assert!(future.as_mut().poll(&mut task).is_pending());
        cx.cancel_fast(CancelKind::User);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            future.as_mut().poll(&mut task),
            Poll::Ready(Err(ManagedToolError::Core(ManagedCoreError::Cancelled)))
        ));
        assert_eq!(state.polls.load(Ordering::SeqCst), 1);
        assert!(state.dropped.load(Ordering::SeqCst));
        assert!(!cancellation.is_cancel_requested());
        contract.check().unwrap();
    }

    #[test]
    fn pre_cancelled_caller_never_enters_owned_work() {
        let cx = Cx::for_testing();
        let contract = contract();
        let cancellation = McpRequestCancellation::new();
        let state = Arc::new(State::default());
        cx.cancel_fast(CancelKind::User);
        let mut future = Box::pin(await_validity(
            &cx,
            &cancellation,
            &contract,
            Waiting(state.clone()),
        ));
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(ManagedToolError::Core(ManagedCoreError::Cancelled)))
        ));
        assert_eq!(state.polls.load(Ordering::SeqCst), 0);
        assert!(state.dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn caller_cancellation_during_a_ready_poll_withholds_and_drops_the_value() {
        let cx = Cx::for_testing();
        let contract = contract();
        let cancellation = McpRequestCancellation::new();
        let state = Arc::new(State::default());
        // `Waiting` is an always-Pending future used here only as a
        // drop-observable PAYLOAD, so this block is deliberately Ready with an
        // awaitable value. Taking clippy's suggestion and awaiting it would
        // make the block Pending forever, there would be no "ready poll" left
        // to cancel during, and the property in this test's name would no
        // longer be exercised at all.
        #[allow(clippy::async_yields_async)]
        let inner = async {
            cx.cancel_fast(CancelKind::User);
            Waiting(state.clone())
        };
        let mut future = Box::pin(await_validity(&cx, &cancellation, &contract, inner));
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(ManagedToolError::Core(ManagedCoreError::Cancelled)))
        ));
        assert!(state.dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn dropping_a_context_waiter_unregisters_only_its_own_wakeup() {
        let cx = Cx::for_testing();
        let contract = contract();
        let cancellation = McpRequestCancellation::new();
        let abandoned_wakes = Arc::new(Wakes::default());
        let sibling_wakes = Arc::new(Wakes::default());
        let abandoned_waker = Waker::from(abandoned_wakes.clone());
        let sibling_waker = Waker::from(sibling_wakes.clone());
        let mut abandoned = Box::pin(await_validity(
            &cx,
            &cancellation,
            &contract,
            std::future::pending::<()>(),
        ));
        let mut sibling = Box::pin(await_validity(
            &cx,
            &cancellation,
            &contract,
            std::future::pending::<()>(),
        ));
        assert!(
            abandoned
                .as_mut()
                .poll(&mut Context::from_waker(&abandoned_waker))
                .is_pending()
        );
        assert!(
            sibling
                .as_mut()
                .poll(&mut Context::from_waker(&sibling_waker))
                .is_pending()
        );
        drop(abandoned);
        let retired_wakes = abandoned_wakes.0.load(Ordering::SeqCst);
        assert!(cx.checkpoint().is_ok());
        assert!(!cancellation.is_cancel_requested());
        contract.check().unwrap();
        cx.cancel_fast(CancelKind::User);
        assert_eq!(abandoned_wakes.0.load(Ordering::SeqCst), retired_wakes);
        assert!(sibling_wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            sibling.as_mut().poll(&mut Context::from_waker(&sibling_waker)),
            Poll::Ready(Err(ManagedToolError::Core(ManagedCoreError::Cancelled)))
        ));
    }

    #[test]
    fn cancelling_one_caller_does_not_poison_a_shared_tool_contract() {
        let cx = Cx::for_testing();
        let sibling_cx = Cx::for_testing();
        let contract = contract();
        let cancellation = McpRequestCancellation::new();
        let mut cancelled = Box::pin(await_validity(
            &cx,
            &cancellation,
            &contract,
            std::future::pending::<()>(),
        ));
        assert!(
            cancelled
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        cx.cancel_fast(CancelKind::User);
        assert!(matches!(
            cancelled
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(ManagedToolError::Core(ManagedCoreError::Cancelled)))
        ));
        let mut sibling = Box::pin(await_validity(
            &sibling_cx,
            &cancellation,
            &contract,
            std::future::ready(42),
        ));
        assert!(matches!(
            sibling
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(42))
        ));
        assert!(sibling_cx.checkpoint().is_ok());
        contract.check().unwrap();
    }

    fn clocked_runtime() -> (
        asupersync::runtime::Runtime,
        asupersync::time::TimerDriverHandle,
        Arc<asupersync::time::VirtualClock>,
    ) {
        use asupersync::runtime::RuntimeBuilder;
        use asupersync::time::{TimerDriverHandle, VirtualClock};

        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        (runtime, timer, clock)
    }

    #[test]
    fn callbacks_use_the_caller_context_and_restore_the_ambient_context() {
        let ambient = Cx::for_testing();
        let _ambient = Cx::set_current(Some(ambient.clone()));
        let cx = Cx::for_testing();
        let contract = contract();
        let cancellation = McpRequestCancellation::new();
        let inner = async {
            Cx::current().unwrap().cancel_fast(CancelKind::User);
            42
        };
        let mut future = Box::pin(await_validity(&cx, &cancellation, &contract, inner));
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(ManagedToolError::Core(ManagedCoreError::Cancelled)))
        ));
        assert!(cx.is_cancel_requested());
        assert!(!ambient.is_cancel_requested());
        Cx::current().unwrap().cancel_fast(CancelKind::User);
        assert!(ambient.is_cancel_requested());
    }

    #[test]
    fn pending_callbacks_restore_the_ambient_context_without_widening_authority() {
        let ambient = Cx::for_testing();
        let _ambient = Cx::set_current(Some(ambient.clone()));
        // The caller holds TIME and nothing else. TIME is not an accommodation:
        // `await_validity` enforces the caller's own deadline and so genuinely
        // needs a clock, which is why a fully stripped `detached_cancel_context`
        // cannot be the subject here. Keeping one capability makes this a test
        // of SELECTIVE propagation -- four dimensions must not appear, the one
        // the caller actually holds must -- which is strictly more than a
        // blanket-stripping assertion would prove.
        let cx = Cx::for_testing().restrict::<cap::CapSet<false, true, false, false, false>>();
        let observed = std::cell::RefCell::new(None);
        let contract = contract();
        let cancellation = McpRequestCancellation::new();
        let inner = poll_fn(|_| {
            // `ambient` above is fully capable, so every `false` here is a
            // capability the callback could only have obtained by escaping the
            // caller's bound through the thread-local lookup.
            let current = Cx::current().unwrap();
            assert!(!current.capabilities().io);
            assert!(!current.capabilities().spawn);
            assert!(!current.capabilities().entropy);
            assert!(!current.capabilities().remote);
            assert!(current.capabilities().time);
            *observed.borrow_mut() = Some(current);
            Poll::<()>::Pending
        });
        let mut future = Box::pin(await_validity(&cx, &cancellation, &contract, inner));
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        observed.borrow().as_ref().unwrap().cancel_fast(CancelKind::User);
        assert!(cx.is_cancel_requested());
        assert!(!ambient.is_cancel_requested());
        Cx::current().unwrap().cancel_fast(CancelKind::User);
        assert!(ambient.is_cancel_requested());
    }

    #[test]
    fn caller_deadline_wakes_stalled_work_on_its_own_clock_not_the_ambient_clock() {
        use asupersync::{Budget, Time};
        use std::time::Duration;

        let (runtime, timer, clock) = clocked_runtime();
        let cx = runtime.request_cx_with_budget(
            Budget::INFINITE.with_deadline(Time::from_nanos(10_000_000)),
        );
        let (foreign_runtime, foreign_timer, foreign_clock) = clocked_runtime();
        foreign_clock.advance(1_000_000_000);
        let foreign_cx = foreign_runtime.request_cx_with_budget(Budget::INFINITE);
        let ambient = Cx::set_current(Some(foreign_cx.clone()));
        let contract = contract();
        let cancellation = McpRequestCancellation::new();
        let state = Arc::new(State::default());
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(await_validity(
            &cx,
            &cancellation,
            &contract,
            Waiting(state.clone()),
        ));
        assert!(future.as_mut().poll(&mut task).is_pending());
        assert!(timer.pending_count() > 0);
        assert_eq!(foreign_timer.pending_count(), 0);
        assert_eq!(Cx::current().unwrap().now(), foreign_cx.now());
        clock.advance(10_000_000);
        assert!(timer.process_timers() > 0);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            future.as_mut().poll(&mut task),
            Poll::Ready(Err(ManagedToolError::Core(ManagedCoreError::TimedOut)))
        ));
        assert_eq!(state.polls.load(Ordering::SeqCst), 1);
        assert!(state.dropped.load(Ordering::SeqCst));
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(foreign_timer.pending_count(), 0);
        assert_eq!(Cx::current().unwrap().now(), foreign_cx.now());
        assert!(!cancellation.is_cancel_requested());
        assert!(!foreign_cx.is_cancel_requested());
        contract.check().unwrap();
        drop(future);
        drop(ambient);
        drop(foreign_cx);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        assert!(foreign_runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn bounded_callers_without_a_driver_refuse_before_owned_work() {
        use asupersync::{Budget, Time};

        let cx = Cx::for_testing_with_budget(
            Budget::INFINITE.with_deadline(Time::from_nanos(u64::MAX)),
        );
        let contract = contract();
        let cancellation = McpRequestCancellation::new();
        let state = Arc::new(State::default());
        let mut future = Box::pin(await_validity(
            &cx,
            &cancellation,
            &contract,
            Waiting(state.clone()),
        ));
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(ManagedToolError::Core(ManagedCoreError::RuntimeUnavailable)))
        ));
        assert_eq!(state.polls.load(Ordering::SeqCst), 0);
        assert!(state.dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn deadline_expiring_inside_a_ready_callback_withholds_its_output() {
        use asupersync::{Budget, Time};
        use std::time::Duration;

        let (runtime, timer, clock) = clocked_runtime();
        let cx = runtime.request_cx_with_budget(
            Budget::INFINITE.with_deadline(Time::from_nanos(10_000_000)),
        );
        let contract = contract();
        let cancellation = McpRequestCancellation::new();
        let state = Arc::new(State::default());
        // Ready-with-an-awaitable on purpose; see the note on
        // `caller_cancellation_during_a_ready_poll_withholds_and_drops_the_value`.
        // Awaiting `Waiting` would remove the ready callback this test needs the
        // expiring deadline to land inside.
        #[allow(clippy::async_yields_async)]
        let inner = async {
            clock.advance(10_000_000);
            Waiting(state.clone())
        };
        let mut future = Box::pin(await_validity(&cx, &cancellation, &contract, inner));
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(ManagedToolError::Core(ManagedCoreError::TimedOut)))
        ));
        assert!(state.dropped.load(Ordering::SeqCst));
        assert_eq!(timer.pending_count(), 0);
        drop(future);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn abandoned_bounded_work_retires_its_timer_and_all_cancellation_waiters() {
        use asupersync::{Budget, Time};
        use std::time::Duration;

        let (runtime, timer, clock) = clocked_runtime();
        let cx = runtime.request_cx_with_budget(
            Budget::INFINITE.with_deadline(Time::from_nanos(10_000_000)),
        );
        let contract = contract();
        let cancellation = McpRequestCancellation::new();
        let state = Arc::new(State::default());
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut future = Box::pin(await_validity(
            &cx,
            &cancellation,
            &contract,
            Waiting(state.clone()),
        ));
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert!(timer.pending_count() > 0);
        drop(future);
        assert!(state.dropped.load(Ordering::SeqCst));
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(Arc::strong_count(&wakes), 2);
        clock.advance(10_000_000);
        assert_eq!(timer.process_timers(), 0);
        cx.cancel_fast(CancelKind::User);
        cancellation.cancel();
        contract.invalidate();
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}
