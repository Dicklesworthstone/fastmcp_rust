//! A caller-polled lifetime fence for schema-bound work, not a second runtime.
//!
//! Register invalidation before polling the owned operation, then recheck after
//! every poll. This closes the pending-renewal/read/resume window without
//! retrying a request, extending a deadline or cancelling the shared login.
//! Already-dispatched side effects cannot be recalled. Dropping a renewal that
//! may have consumed its refresh token retains the session's existing refusal
//! to reuse that uncertain lineage.

use std::future::{Future, poll_fn};
use std::task::Poll;

use asupersync::Cx;
use asupersync::channel::oneshot;
use fastmcp_core::McpRequestCancellation;

use super::{ManagedCoreError, ManagedToolError, ToolContract, check_tool_call};

// T deliberately includes the inner Result. Interaction-local answer refusals
// must retain their original type and challenge; invalidation is terminal and
// must not enter that correctable-input branch or restore the owned operation.
pub(super) async fn await_validity<T>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    contract: &ToolContract,
    future: impl Future<Output = T>,
) -> Result<T, ManagedToolError> {
    let mut invalidated = std::pin::pin!(contract.invalidation.cancelled());
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    // The pinned asupersync 0.5 API has no public Cx::cancelled observer.
    // An unsent, retained oneshot gives us its cancellation-safe receive
    // registration without spawning work, polling a timer or inventing a Cx.
    // Keep the sender alive across the await: only the caller's checkpoint
    // refusal can complete this receive. Drop unregisters this waiter alone.
    let (_keep_open, mut context_receiver) = oneshot::channel::<()>();
    let mut context_cancelled = std::pin::pin!(context_receiver.recv(cx));
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        check_tool_call(cx, cancellation, contract)?;
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
}
