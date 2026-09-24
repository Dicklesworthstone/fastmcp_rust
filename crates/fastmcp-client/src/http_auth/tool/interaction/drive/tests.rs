use super::*;
use fastmcp_core::block_on;
use fastmcp_protocol::{ClientCapabilities, CoreRequest, FinalRequestMeta, FinalTool, RequestId};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use serde_json::json;
use std::future::{pending, ready};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

fn contract() -> ToolContract {
    ToolContract::admit(FinalTool {
        name: "checkout".to_owned(), title: None, description: None, icons: None,
        input_schema: json!({"type":"object"}), output_schema: None,
        annotations: None, meta: None,
    }).unwrap()
}

fn input() -> Box<InputRequiredResult> {
    let params = json!({"name":"checkout", "_meta":FinalRequestMeta::new(ClientCapabilities::default())});
    let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap();
    let result = request.decode_result(r#"{"resultType":"input_required","requestState":"  opaque\u0000  "}"#).unwrap();
    Box::new(crate::http_auth::rpc::interaction::input_required(&result).unwrap().clone())
}

fn reply() -> ManagedInputReply {
    ManagedInputReply { request_id: RequestId::Number(2), input_responses: None }
}

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

struct Waiting { polls: Arc<AtomicUsize>, dropped: Arc<AtomicBool> }
impl Future for Waiting {
    type Output = Result<ManagedInputReply, ManagedInteractionError>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}
impl Drop for Waiting {
    fn drop(&mut self) { self.dropped.store(true, Ordering::SeqCst); }
}

#[test]
fn no_callback_construction_after_tool_catalog_or_request_invalidation() {
    for mode in 0..3 {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let mut contract = contract();
        match mode {
            0 => contract.invalidate(),
            1 => contract.catalog_invalidated = Some(Arc::new(AtomicBool::new(true))),
            _ => cancellation.cancel(),
        }
        let mut calls = 0;
        let mut resolver = |_| { calls += 1; ready(Ok::<_, ManagedInteractionError>(reply())) };
        assert!(begin_resolution(&cx, &cancellation, &contract, &mut resolver, input()).is_err());
        assert_eq!(calls, 0);
    }
}

#[test]
fn a_live_resolver_receives_exact_state_and_preserves_answer_presence() {
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let contract = contract();
    let mut calls = 0;
    let mut resolver = |input: Box<InputRequiredResult>| {
        calls += 1;
        assert_eq!(input.request_state(), Some("  opaque\0  "));
        assert!(input.input_requests().is_none());
        ready(Ok(reply()))
    };
    let prepared = begin_resolution(&cx, &cancellation, &contract, &mut resolver, input());
    let result = block_on(finish_resolution(&cx, &cancellation, &contract, prepared)).unwrap();
    assert_eq!(calls, 1);
    assert_eq!(result.request_id, RequestId::Number(2));
    assert!(result.input_responses.is_none());
    assert!(!contract.is_invalidated());
    assert!(!cancellation.is_cancel_requested());
}

#[test]
fn constructor_invalidation_drops_the_unpolled_resolver_future() {
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let contract = contract();
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let mut resolver = |_| {
        contract.invalidate();
        Waiting { polls: polls.clone(), dropped: dropped.clone() }
    };
    let prepared = begin_resolution(&cx, &cancellation, &contract, &mut resolver, input());
    assert!(matches!(block_on(finish_resolution(&cx, &cancellation, &contract, prepared)),
        Err(ManagedInteractionError::AbortedByHost)));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn a_ready_answer_cannot_cross_invalidation_in_the_same_poll() {
    for cancel in [false, true] {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let contract = contract();
        let inner = async {
            if cancel { cancellation.cancel(); } else { contract.invalidate(); }
            Ok(reply())
        };
        // The outer fence is the production driver's error boundary; the inner
        // one stops the core driver before it can consume a ready answer.
        let result = block_on(await_validity(&cx, &cancellation, &contract,
            finish_resolution(&cx, &cancellation, &contract, Ok(inner))));
        if cancel {
            assert!(matches!(result, Err(ManagedToolError::Core(crate::http_auth::rpc::ManagedCoreError::Cancelled))));
        } else {
            assert!(matches!(result, Err(ManagedToolError::Invalidated)));
        }
    }
}

#[test]
fn pending_resolver_is_woken_and_dropped_without_polling_it_again() {
    for cancel in [false, true] {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let contract = contract();
        let polls = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let inner = Waiting { polls: polls.clone(), dropped: dropped.clone() };
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut task = Context::from_waker(&waker);
        let mut future = Box::pin(finish_resolution(&cx, &cancellation, &contract, Ok(inner)));
        assert!(future.as_mut().poll(&mut task).is_pending());
        if cancel { cancellation.cancel(); } else { contract.invalidate(); }
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(future.as_mut().poll(&mut task), Poll::Ready(Err(ManagedInteractionError::AbortedByHost))));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(cx.checkpoint().is_ok());
    }
}

#[test]
fn resolver_errors_keep_their_core_kind_without_invalidating_siblings() {
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let contract = contract();
    for error in [ManagedInteractionError::AbortedByHost, ManagedInteractionError::InvalidInputResponses] {
        let declined = matches!(error, ManagedInteractionError::AbortedByHost);
        let result = block_on(finish_resolution(&cx, &cancellation, &contract,
            Ok(ready(Err::<ManagedInputReply, _>(error)))));
        assert_eq!(matches!(result, Err(ManagedInteractionError::AbortedByHost)), declined);
        if !declined { assert!(matches!(result, Err(ManagedInteractionError::InvalidInputResponses))); }
    }
    assert!(contract.check().is_ok());
    assert!(!cancellation.is_cancel_requested());
}

#[test]
fn notification_callbacks_are_fenced_before_and_after_host_entry() {
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let contract = contract();
    let mut calls = 0;
    let mut notify = |_| { calls += 1; Ok(()) };
    deliver_notification(&cx, &cancellation, &contract, &mut notify,
        Box::new(ServerNotification::ToolsListChanged(None))).unwrap();
    assert_eq!(calls, 1);
    let mut invalidating = |_| { contract.invalidate(); Ok(()) };
    assert!(matches!(deliver_notification(&cx, &cancellation, &contract, &mut invalidating,
        Box::new(ServerNotification::ToolsListChanged(None))), Err(ManagedInteractionError::AbortedByHost)));
    let mut forbidden = |_| { calls += 1; Ok(()) };
    assert!(deliver_notification(&cx, &cancellation, &contract, &mut forbidden,
        Box::new(ServerNotification::ToolsListChanged(None))).is_err());
    assert_eq!(calls, 1);
}

#[test]
fn dropping_a_polled_resolver_releases_its_owned_input_work() {
    struct Guard(Arc<AtomicBool>);
    impl Drop for Guard { fn drop(&mut self) { self.0.store(true, Ordering::SeqCst); } }
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let contract = contract();
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Guard(dropped.clone());
    let inner = async move {
        let _guard = guard;
        pending::<Result<ManagedInputReply, ManagedInteractionError>>().await
    };
    let mut future = Box::pin(finish_resolution(&cx, &cancellation, &contract, Ok(inner)));
    assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    drop(future);
    assert!(dropped.load(Ordering::SeqCst));
    assert!(contract.check().is_ok());
    assert!(!cancellation.is_cancel_requested());
}
