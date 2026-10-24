use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use asupersync::Budget;
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use serde_json::{Value, json};

use super::*;
use crate::http_auth::sampling::{
    FinalCreateMessageResult, FinalEmbeddedCreateMessageParams, SamplingHost, SamplingHostError,
    SamplingRunLimits, SamplingToolLoopLimits, run_sampling_tool_loop,
};

#[derive(Default)]
struct Counts {
    factories: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    drops: AtomicUsize,
    samples: AtomicUsize,
    approvals: AtomicUsize,
    selections: AtomicUsize,
    sequential: AtomicUsize,
}

struct Control {
    ready: AtomicBool,
    cancel_on_poll: AtomicBool,
    value: Mutex<Option<Result<SamplingContentBlock, SamplingHostError>>>,
    waker: Mutex<Option<Waker>>,
}

impl Control {
    fn release(&self) {
        self.ready.store(true, Ordering::SeqCst);
        let waker = self.waker.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn replace(&self, result: Result<SamplingContentBlock, SamplingHostError>) {
        *self.value.lock().unwrap() = Some(result);
    }
}

struct ToolWait<'a> {
    control: &'a Control,
    counts: &'a Counts,
    cancellation: &'a McpRequestCancellation,
}

impl Future for ToolWait<'_> {
    type Output = Result<SamplingContentBlock, SamplingHostError>;

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        if self.control.cancel_on_poll.load(Ordering::SeqCst) {
            let _ = self.cancellation.cancel();
        }
        if self.control.ready.load(Ordering::SeqCst) {
            Poll::Ready(self.control.value.lock().unwrap().take().unwrap())
        } else {
            *self.control.waker.lock().unwrap() = Some(task.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for ToolWait<'_> {
    fn drop(&mut self) {
        self.control.waker.lock().unwrap().take();
        self.counts.active.fetch_sub(1, Ordering::SeqCst);
        self.counts.drops.fetch_add(1, Ordering::SeqCst);
    }
}

struct Host {
    controls: Vec<Arc<Control>>,
    counts: Arc<Counts>,
    requests: Arc<Mutex<Vec<Value>>>,
    responses: VecDeque<FinalCreateMessageResult>,
    width: Option<usize>,
    deny: bool,
}

impl SamplingHost for Host {
    fn sample<'a>(
        &'a mut self,
        _cx: &'a Cx,
        _cancellation: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedCreateMessageParams,
    ) -> SamplingHostFuture<'a, FinalCreateMessageResult> {
        self.counts.samples.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .unwrap()
            .push(serde_json::to_value(request).unwrap());
        let response = self.responses.pop_front().expect("unexpected model retry");
        Box::pin(async move { Ok(response) })
    }

    fn approve_tools<'a>(
        &'a mut self,
        _cx: &'a Cx,
        _cancellation: &'a McpRequestCancellation,
        _calls: &'a [SamplingContentBlock],
    ) -> SamplingHostFuture<'a, ()> {
        self.counts.approvals.fetch_add(1, Ordering::SeqCst);
        let denied = self.deny;
        Box::pin(async move {
            if denied {
                Err(SamplingHostError::Denied)
            } else {
                Ok(())
            }
        })
    }

    fn execute_tool<'a>(
        &'a mut self,
        cx: &'a Cx,
        cancellation: &'a McpRequestCancellation,
        call: &'a SamplingContentBlock,
    ) -> SamplingHostFuture<'a, SamplingContentBlock> {
        self.counts.sequential.fetch_add(1, Ordering::SeqCst);
        ParallelSamplingToolExecutor::execute_tool(self, cx, cancellation, call)
    }

    fn parallel_tools(&self) -> Option<ParallelSamplingTools<'_>> {
        self.counts.selections.fetch_add(1, Ordering::SeqCst);
        self.width
            .map(|width| ParallelSamplingTools::new(self, width).unwrap())
    }
}

impl ParallelSamplingToolExecutor for Host {
    fn execute_tool<'a>(
        &'a self,
        _cx: &'a Cx,
        cancellation: &'a McpRequestCancellation,
        call: &'a SamplingContentBlock,
    ) -> SamplingHostFuture<'a, SamplingContentBlock> {
        let SamplingContentBlock::ToolUse { id, .. } = call else {
            panic!("unadmitted tool reached executor");
        };
        let index = id.parse::<usize>().unwrap();
        // Count the factory, not just future polling. A queued callback must
        // never get this far after failure, denial or cancellation.
        self.counts.factories.fetch_add(1, Ordering::SeqCst);
        let active = self.counts.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.counts.peak.fetch_max(active, Ordering::SeqCst);
        Box::pin(ToolWait {
            control: &self.controls[index],
            counts: &self.counts,
            cancellation,
        })
    }
}

fn request() -> FinalEmbeddedCreateMessageParams {
    serde_json::from_value(json!({
        "messages": [{"role": "user", "content": {"type": "text", "text": "look up"}}],
        "maxTokens": 100,
        "tools": [{"name": "lookup", "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object", "required": ["value"],
                "properties": {"value": {"type": "integer"}}}}]
    }))
    .unwrap()
}

fn answer(index: usize) -> SamplingContentBlock {
    serde_json::from_value(json!({
        "type": "tool_result", "toolUseId": index.to_string(),
        "content": [{"type": "text", "text": format!("answer-{index}")}],
        "structuredContent": {"value": index},
        "_meta": {"example.org/source": index.to_string()}
    }))
    .unwrap()
}

fn response(content: Value) -> FinalCreateMessageResult {
    serde_json::from_value(json!({
        "role": "assistant", "model": "host-model", "content": content
    }))
    .unwrap()
}

fn host(count: usize, width: Option<usize>) -> Host {
    Host {
        controls: (0..count)
            .map(|index| {
                Arc::new(Control {
                    ready: AtomicBool::new(false),
                    cancel_on_poll: AtomicBool::new(false),
                    value: Mutex::new(Some(Ok(answer(index)))),
                    waker: Mutex::new(None),
                })
            })
            .collect(),
        counts: Arc::new(Counts::default()),
        requests: Arc::new(Mutex::new(Vec::new())),
        responses: VecDeque::from([
            response(Value::Array(
                (0..count)
                    .map(|index| {
                        json!({"type": "tool_use", "id": index.to_string(),
                        "name": "lookup", "input": {}})
                    })
                    .collect(),
            )),
            response(json!({"type": "text", "text": "done"})),
        ]),
        width,
        deny: false,
    }
}

struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn scheduled() -> Arc<WakeCount> {
    Arc::new(WakeCount(AtomicUsize::new(1)))
}

// Poll only scheduled work. In particular, no manual repoll can hide a lost
// child/cancellation/timer wakeup. The finite ceiling detects busy loops.
fn pump<F: Future>(future: Pin<&mut F>, wakes: &Arc<WakeCount>) -> Poll<F::Output> {
    let waker = Waker::from(Arc::clone(wakes));
    let mut task = Context::from_waker(&waker);
    let mut future = future;
    for _ in 0..128 {
        if wakes.0.swap(0, Ordering::SeqCst) == 0 {
            return Poll::Pending;
        }
        if let Poll::Ready(result) = future.as_mut().poll(&mut task) {
            return Poll::Ready(result);
        }
    }
    panic!("sampling loop remained runnable without a bounded yield");
}

fn finish<F: Future>(future: Pin<&mut F>, wakes: &Arc<WakeCount>) -> F::Output {
    match pump(future, wakes) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("sampling failed to finish on its scheduled wakeups"),
    }
}

fn with_context(budget: Budget, test: impl FnOnce(&Cx, &TimerDriverHandle, &Arc<VirtualClock>)) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .with_timer_driver(timer.clone())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(budget);
    test(&cx, &timer, &clock);
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn bounded_parallel_tools_overlap_and_reassemble_in_model_order() {
    with_context(Budget::INFINITE, |cx, timer, _| {
        let mut host = host(5, Some(2));
        let controls = host.controls.clone();
        let counts = Arc::clone(&host.counts);
        let requests = Arc::clone(&host.requests);
        let cancellation = McpRequestCancellation::new();
        let wakes = scheduled();
        let mut run = Box::pin(run_sampling_tool_loop(
            cx,
            &cancellation,
            request(),
            SamplingRunLimits::default(),
            &mut host,
        ));
        assert!(pump(run.as_mut(), &wakes).is_pending());
        assert_eq!(counts.factories.load(Ordering::SeqCst), 2);
        assert_eq!(counts.active.load(Ordering::SeqCst), 2);

        // Complete later slots first. Tool 0 must not block refilling a free
        // slot, but the next model request must keep the original ID order.
        for (index, expected) in [(1, 3), (2, 4), (0, 5), (3, 5)] {
            controls[index].release();
            assert!(pump(run.as_mut(), &wakes).is_pending());
            assert_eq!(counts.factories.load(Ordering::SeqCst), expected);
            assert!(counts.active.load(Ordering::SeqCst) <= 2);
        }
        controls[4].release();
        let result = finish(run.as_mut(), &wakes).unwrap();
        assert_eq!(result.model_rounds, 2);
        assert_eq!(result.executed_tools, 5);
        assert_eq!(counts.peak.load(Ordering::SeqCst), 2);
        assert_eq!(counts.active.load(Ordering::SeqCst), 0);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 5);
        assert_eq!(counts.sequential.load(Ordering::SeqCst), 0);
        assert_eq!(counts.approvals.load(Ordering::SeqCst), 1);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for index in 0..5 {
            assert_eq!(
                requests[1]["messages"][2]["content"][index],
                serde_json::to_value(answer(index)).unwrap()
            );
        }
        assert_eq!(
            serde_json::to_value(result.response).unwrap()["content"]["text"],
            "done"
        );
        assert_eq!(timer.pending_count(), 0);
    });
}

#[test]
fn no_parallel_executor_preserves_sequential_admission() {
    with_context(Budget::INFINITE, |cx, _, _| {
        let mut host = host(2, None);
        let controls = host.controls.clone();
        let counts = Arc::clone(&host.counts);
        let cancellation = McpRequestCancellation::new();
        let wakes = scheduled();
        let mut run = Box::pin(run_sampling_tool_loop(
            cx,
            &cancellation,
            request(),
            SamplingRunLimits::default(),
            &mut host,
        ));
        assert!(pump(run.as_mut(), &wakes).is_pending());
        assert_eq!(counts.factories.load(Ordering::SeqCst), 1);
        controls[1].release();
        assert!(pump(run.as_mut(), &wakes).is_pending());
        assert_eq!(counts.factories.load(Ordering::SeqCst), 1);
        controls[0].release();
        assert_eq!(finish(run.as_mut(), &wakes).unwrap().executed_tools, 2);
        assert_eq!(counts.peak.load(Ordering::SeqCst), 1);
        assert_eq!(counts.sequential.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn invalid_concurrency_is_refused_without_constructing_host_work() {
    let host = host(1, None);
    for width in [0, 65, usize::MAX] {
        assert_eq!(
            ParallelSamplingTools::new(&host, width).err(),
            Some(SamplingRunError::InvalidLimits)
        );
    }
    for width in [1, 64] {
        assert!(ParallelSamplingTools::new(&host, width).is_ok());
    }
    assert_eq!(host.counts.factories.load(Ordering::SeqCst), 0);
}

#[test]
fn complete_batch_admission_and_consent_precede_executor_selection() {
    for invalid in [false, true] {
        with_context(Budget::INFINITE, |cx, _, _| {
            let mut host = host(2, Some(2));
            if invalid {
                host.responses[0] = response(json!([
                    {"type": "tool_use", "id": "0", "name": "lookup", "input": {}},
                    {"type": "tool_use", "id": "1", "name": "undeclared", "input": {}}
                ]));
            } else {
                host.deny = true;
            }
            let counts = Arc::clone(&host.counts);
            let cancellation = McpRequestCancellation::new();
            let mut run = Box::pin(run_sampling_tool_loop(
                cx,
                &cancellation,
                request(),
                SamplingRunLimits::default(),
                &mut host,
            ));
            let error = finish(run.as_mut(), &scheduled()).err().unwrap();
            assert_eq!(
                error,
                if invalid {
                    SamplingRunError::Protocol(SamplingToolLoopError::UnknownTool)
                } else {
                    SamplingRunError::Host {
                        stage: SamplingStage::Approval,
                        reason: SamplingHostError::Denied,
                    }
                }
            );
            assert_eq!(
                counts.approvals.load(Ordering::SeqCst),
                usize::from(!invalid)
            );
            assert_eq!(counts.selections.load(Ordering::SeqCst), 0);
            assert_eq!(counts.factories.load(Ordering::SeqCst), 0);
        });
    }
}

#[test]
fn failed_active_tool_drops_siblings_and_never_starts_queued_work() {
    for first_ready in [false, true] {
        with_context(Budget::INFINITE, |cx, timer, _| {
            let mut host = host(4, Some(2));
            host.controls[0].ready.store(first_ready, Ordering::SeqCst);
            host.controls[1].replace(Err(SamplingHostError::Failed));
            host.controls[1].release();
            let counts = Arc::clone(&host.counts);
            let cancellation = McpRequestCancellation::new();
            let mut run = Box::pin(run_sampling_tool_loop(
                cx,
                &cancellation,
                request(),
                SamplingRunLimits::default(),
                &mut host,
            ));
            let error = finish(run.as_mut(), &scheduled()).err().unwrap();
            assert_eq!(
                error,
                SamplingRunError::Host {
                    stage: SamplingStage::Tool,
                    reason: SamplingHostError::Failed,
                }
            );
            assert_eq!(counts.factories.load(Ordering::SeqCst), 2);
            assert_eq!(counts.drops.load(Ordering::SeqCst), 2);
            assert_eq!(counts.active.load(Ordering::SeqCst), 0);
            assert_eq!(counts.samples.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
        });
    }
}

#[test]
fn malformed_or_over_budget_results_refuse_before_refilling() {
    for variant in 0..3 {
        with_context(Budget::INFINITE, |cx, _, _| {
            let mut host = host(4, Some(2));
            let mut value = serde_json::to_value(answer(1)).unwrap();
            let (maximum, expected) = match variant {
                0 => {
                    value["toolUseId"] = json!("foreign");
                    (
                        4096,
                        SamplingRunError::Protocol(SamplingToolLoopError::InvalidToolResults),
                    )
                }
                1 => {
                    value["structuredContent"] = json!({"value": "not an integer"});
                    (
                        4096,
                        SamplingRunError::Protocol(SamplingToolLoopError::InvalidToolOutput),
                    )
                }
                _ => (1, SamplingRunError::ToolResultByteLimit),
            };
            host.controls[1].replace(Ok(serde_json::from_value(value).unwrap()));
            host.controls[1].release();
            let counts = Arc::clone(&host.counts);
            let cancellation = McpRequestCancellation::new();
            let limits = SamplingRunLimits::new(
                SamplingToolLoopLimits::default(),
                Duration::from_secs(1),
                maximum,
            )
            .unwrap();
            let mut run = Box::pin(run_sampling_tool_loop(
                cx,
                &cancellation,
                request(),
                limits,
                &mut host,
            ));
            assert_eq!(finish(run.as_mut(), &scheduled()).err(), Some(expected));
            assert_eq!(counts.factories.load(Ordering::SeqCst), 2);
            assert_eq!(counts.active.load(Ordering::SeqCst), 0);
            assert_eq!(counts.samples.load(Ordering::SeqCst), 1);
        });
    }
}

#[test]
fn cancellation_wakes_all_pending_tools_without_a_child_wakeup() {
    for parent in [false, true] {
        with_context(Budget::INFINITE, |cx, timer, _| {
            let mut host = host(4, Some(2));
            let counts = Arc::clone(&host.counts);
            let cancellation = McpRequestCancellation::new();
            let wakes = scheduled();
            let mut run = Box::pin(run_sampling_tool_loop(
                cx,
                &cancellation,
                request(),
                SamplingRunLimits::default(),
                &mut host,
            ));
            assert!(pump(run.as_mut(), &wakes).is_pending());
            assert_eq!(counts.active.load(Ordering::SeqCst), 2);
            assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
            if parent {
                cx.set_cancel_requested(true);
            } else {
                assert!(cancellation.cancel());
            }
            assert!(
                wakes.0.load(Ordering::SeqCst) > 0,
                "cancellation did not schedule the owner"
            );
            assert_eq!(
                finish(run.as_mut(), &wakes).err(),
                Some(SamplingRunError::Cancelled)
            );
            assert_eq!(counts.factories.load(Ordering::SeqCst), 2);
            assert_eq!(counts.active.load(Ordering::SeqCst), 0);
            assert_eq!(timer.pending_count(), 0);
            if !parent {
                assert!(!cx.is_cancel_requested());
            }
        });
    }
}

#[test]
fn run_and_caller_deadlines_wake_the_pending_batch() {
    for parent in [false, true] {
        let budget = if parent {
            Budget::INFINITE.with_deadline(Time::from_nanos(5_000_000))
        } else {
            Budget::INFINITE
        };
        with_context(budget, |cx, timer, clock| {
            let mut host = host(4, Some(2));
            let counts = Arc::clone(&host.counts);
            let cancellation = McpRequestCancellation::new();
            let wakes = scheduled();
            let limits = SamplingRunLimits::new(
                SamplingToolLoopLimits::default(),
                Duration::from_millis(10),
                4096,
            )
            .unwrap();
            let mut run = Box::pin(run_sampling_tool_loop(
                cx,
                &cancellation,
                request(),
                limits,
                &mut host,
            ));
            assert!(pump(run.as_mut(), &wakes).is_pending());
            clock.advance(if parent { 5_000_000 } else { 10_000_000 });
            assert!(timer.process_timers() > 0);
            assert!(wakes.0.load(Ordering::SeqCst) > 0);
            assert_eq!(
                finish(run.as_mut(), &wakes).err(),
                Some(SamplingRunError::TimedOut)
            );
            assert_eq!(counts.factories.load(Ordering::SeqCst), 2);
            assert_eq!(counts.active.load(Ordering::SeqCst), 0);
            assert_eq!(timer.pending_count(), 0);
        });
    }
}

#[test]
fn dropping_a_polled_batch_retires_tools_timer_and_wakeups() {
    with_context(Budget::INFINITE, |cx, timer, clock| {
        let mut host = host(4, Some(2));
        let counts = Arc::clone(&host.counts);
        let controls = host.controls.clone();
        let cancellation = McpRequestCancellation::new();
        let wakes = scheduled();
        let mut run = Box::pin(run_sampling_tool_loop(
            cx,
            &cancellation,
            request(),
            SamplingRunLimits::default(),
            &mut host,
        ));
        assert!(pump(run.as_mut(), &wakes).is_pending());
        drop(run);
        assert_eq!(counts.factories.load(Ordering::SeqCst), 2);
        assert_eq!(counts.active.load(Ordering::SeqCst), 0);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 2);
        assert!(
            controls
                .iter()
                .all(|control| control.waker.lock().unwrap().is_none())
        );
        assert_eq!(timer.pending_count(), 0);
        assert!(cancellation.cancel());
        cx.set_cancel_requested(true);
        clock.advance(600_000_000_000);
        assert_eq!(timer.process_timers(), 0);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn mid_poll_cancellation_prevents_later_callback_construction() {
    for ready in [false, true] {
        with_context(Budget::INFINITE, |cx, _, _| {
            let mut host = host(3, Some(3));
            host.controls[0]
                .cancel_on_poll
                .store(true, Ordering::SeqCst);
            host.controls[0].ready.store(ready, Ordering::SeqCst);
            let counts = Arc::clone(&host.counts);
            let cancellation = McpRequestCancellation::new();
            let mut run = Box::pin(run_sampling_tool_loop(
                cx,
                &cancellation,
                request(),
                SamplingRunLimits::default(),
                &mut host,
            ));
            assert_eq!(
                finish(run.as_mut(), &scheduled()).err(),
                Some(SamplingRunError::Cancelled)
            );
            assert_eq!(counts.factories.load(Ordering::SeqCst), 1);
            assert_eq!(counts.active.load(Ordering::SeqCst), 0);
            assert!(!cx.is_cancel_requested());
        });
    }
}
