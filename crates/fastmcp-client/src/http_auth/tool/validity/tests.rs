use super::*;
use fastmcp_protocol::FinalTool;
use serde_json::json;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

fn contract() -> ToolContract {
    ToolContract::admit(FinalTool {
        name: "calculate".to_owned(), title: None, description: None, icons: None,
        input_schema: json!({"type":"object"}), output_schema: None,
        annotations: None, meta: None,
    }).unwrap()
}

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

struct Waiting {
    polls: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}
impl Future for Waiting {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}
impl Drop for Waiting {
    fn drop(&mut self) { self.dropped.store(true, Ordering::SeqCst); }
}

fn waiting() -> (Waiting, Arc<AtomicUsize>, Arc<AtomicBool>) {
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    (Waiting { polls: polls.clone(), dropped: dropped.clone() }, polls, dropped)
}

#[test]
fn invalidation_wakes_pending_work_and_prevents_another_inner_poll() {
    let cx = Cx::for_testing();
    let contract = contract();
    let cancellation = McpRequestCancellation::new();
    let (inner, polls, dropped) = waiting();
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut task = Context::from_waker(&waker);
    let mut future = Box::pin(await_validity(&cx, &cancellation, &contract, inner));
    assert!(future.as_mut().poll(&mut task).is_pending());
    contract.invalidate();
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(future.as_mut().poll(&mut task), Poll::Ready(Err(ManagedToolError::Invalidated))));
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert!(dropped.load(Ordering::SeqCst));
    assert!(!cancellation.is_cancel_requested());
    assert!(cx.checkpoint().is_ok());
}

#[test]
fn invalidation_before_first_poll_drops_work_without_entering_it() {
    let cx = Cx::for_testing();
    let contract = contract();
    let cancellation = McpRequestCancellation::new();
    let (inner, polls, dropped) = waiting();
    contract.invalidate();
    let mut future = Box::pin(await_validity(&cx, &cancellation, &contract, inner));
    assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(ManagedToolError::Invalidated))));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn every_waiting_clone_is_woken_not_only_the_most_recent_reader() {
    let cx = Cx::for_testing();
    let contract = Arc::new(contract());
    let cancellation = McpRequestCancellation::new();
    let wakes: Vec<_> = (0..4).map(|_| Arc::new(Wakes::default())).collect();
    let mut readers: Vec<_> = (0..4).map(|_| Box::pin(await_validity(
        &cx, &cancellation, &contract, std::future::pending::<()>(),
    ))).collect();
    for (reader, wakes) in readers.iter_mut().zip(&wakes) {
        let waker = Waker::from(wakes.clone());
        assert!(reader.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }
    let clone = contract.clone();
    clone.invalidate();
    for (reader, wakes) in readers.iter_mut().zip(&wakes) {
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(reader.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(ManagedToolError::Invalidated))));
    }
}

#[test]
fn invalidation_during_poll_withholds_a_ready_value_and_drops_it() {
    struct Value(Arc<AtomicBool>);
    impl Drop for Value {
        fn drop(&mut self) { self.0.store(true, Ordering::SeqCst); }
    }
    let cx = Cx::for_testing();
    let contract = contract();
    let cancellation = McpRequestCancellation::new();
    let dropped = Arc::new(AtomicBool::new(false));
    let inner = async { contract.invalidate(); Value(dropped.clone()) };
    let mut future = Box::pin(await_validity(&cx, &cancellation, &contract, inner));
    assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(ManagedToolError::Invalidated))));
    assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn invalidation_during_pending_poll_drops_the_owned_operation() {
    let cx = Cx::for_testing();
    let contract = contract();
    let cancellation = McpRequestCancellation::new();
    let (owned, _, dropped) = waiting();
    let inner = async {
        let _owned = owned;
        contract.invalidate();
        std::future::pending::<()>().await;
    };
    let mut future = Box::pin(await_validity(&cx, &cancellation, &contract, inner));
    assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(ManagedToolError::Invalidated))));
    assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn request_cancellation_stays_distinct_and_does_not_invalidate_the_contract() {
    let cx = Cx::for_testing();
    let contract = contract();
    let cancellation = McpRequestCancellation::new();
    let (inner, polls, dropped) = waiting();
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut future = Box::pin(await_validity(&cx, &cancellation, &contract, inner));
    assert!(future.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    cancellation.cancel();
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(future.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Err(ManagedToolError::Core(ManagedCoreError::Cancelled)))));
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert!(dropped.load(Ordering::SeqCst));
    contract.check().unwrap();
}

#[test]
fn dropping_one_waiter_does_not_cancel_the_contract_or_another_waiter() {
    let cx = Cx::for_testing();
    let contract = contract();
    let cancellation = McpRequestCancellation::new();
    let (inner, _, dropped) = waiting();
    let mut abandoned = Box::pin(await_validity(&cx, &cancellation, &contract, inner));
    assert!(abandoned.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    drop(abandoned);
    assert!(dropped.load(Ordering::SeqCst));
    contract.check().unwrap();
    assert!(!cancellation.is_cancel_requested());
    let mut sibling = Box::pin(await_validity(&cx, &cancellation, &contract, std::future::ready(42)));
    assert!(matches!(sibling.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Ok(42))));
}

#[test]
fn a_different_contract_and_correctable_inner_errors_are_preserved() {
    let cx = Cx::for_testing();
    let first = contract();
    let sibling = contract();
    let cancellation = McpRequestCancellation::new();
    first.invalidate();
    let mut future = Box::pin(await_validity(&cx, &cancellation, &sibling,
        std::future::ready(Err::<(), _>("correctable local refusal"))));
    assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(Err("correctable local refusal")))));
    sibling.check().unwrap();
}
