//! The production sampling runner must not widen its host's effect authority.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Waker};

use asupersync::Budget;
use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use serde_json::json;

use super::*;

const ALL: u8 = 31;
const TIME: u8 = 2;

fn row(cx: &Cx) -> u8 {
    let c = cx.capabilities();
    u8::from(c.spawn)
        | (u8::from(c.time) << 1)
        | (u8::from(c.entropy) << 2)
        | (u8::from(c.io) << 3)
        | (u8::from(c.remote) << 4)
}

fn mask(bits: u8) -> CapMask {
    let mut mask = CapMask::all();
    for (bit, without) in [
        (1, CapSet::<false, true, true, true, true>::MASK),
        (TIME, CapSet::<true, false, true, true, true>::MASK),
        (4, CapSet::<true, true, false, true, true>::MASK),
        (8, CapSet::<true, true, true, false, true>::MASK),
        (16, CapSet::<true, true, true, true, false>::MASK),
    ] {
        if bits & bit == 0 {
            mask = mask.intersect(without);
        }
    }
    mask
}

fn held(cx: &Cx, bits: u8) -> Cx {
    let _caller = Cx::set_current(Some(cx.clone()));
    let _restriction = Cx::push_restriction(mask(bits));
    Cx::current().unwrap()
}

fn runtime(test: impl FnOnce(&Cx, &TimerDriverHandle)) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(clock);
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .with_timer_driver(timer.clone())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    test(&cx, &timer);
    assert_eq!(timer.pending_count(), 0);
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn request() -> FinalEmbeddedCreateMessageParams {
    serde_json::from_value(json!({
        "messages":[{"role":"user","content":{"type":"text","text":"echo"}}],
        "maxTokens":32,
        "tools":[{"name":"echo","inputSchema":{"type":"object"}}]
    }))
    .unwrap()
}

struct Host {
    expected: u8,
    responses: VecDeque<FinalCreateMessageResult>,
    calls: Vec<&'static str>,
    parallel_hooks: AtomicUsize,
    panic_in_model: bool,
}

impl Host {
    fn new(expected: u8) -> Self {
        let responses = [
            json!({"role":"assistant","model":"test","content":[
                {"type":"tool_use","id":"one","name":"echo","input":{}}
            ]}),
            json!({"role":"assistant","model":"test","content":[
                {"type":"text","text":"done"}
            ]}),
        ];
        Self {
            expected,
            responses: responses
                .into_iter()
                .map(|value| serde_json::from_value(value).unwrap())
                .collect(),
            calls: Vec::new(),
            parallel_hooks: AtomicUsize::new(0),
            panic_in_model: false,
        }
    }

    fn check(&self, cx: &Cx) {
        let current = Cx::current().unwrap();
        assert_eq!(row(&current), self.expected);
        assert_eq!(current.task_id(), cx.task_id());
        assert!(current.timer_driver().is_some());
    }
}

impl SamplingHost for Host {
    fn sample<'a>(
        &'a mut self,
        cx: &'a Cx,
        _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedCreateMessageParams,
    ) -> SamplingHostFuture<'a, FinalCreateMessageResult> {
        self.check(cx);
        self.calls.push("model");
        assert!(!self.panic_in_model, "model callback unwind probe");
        let response = self.responses.pop_front().expect("no model replay");
        Box::pin(async move {
            self.check(cx);
            Ok(response)
        })
    }

    fn approve_tools<'a>(
        &'a mut self,
        cx: &'a Cx,
        _: &'a McpRequestCancellation,
        calls: &'a [SamplingContentBlock],
    ) -> SamplingHostFuture<'a, ()> {
        self.check(cx);
        assert_eq!(calls.len(), 1);
        self.calls.push("approve");
        Box::pin(async move {
            self.check(cx);
            Ok(())
        })
    }

    fn execute_tool<'a>(
        &'a mut self,
        cx: &'a Cx,
        _: &'a McpRequestCancellation,
        call: &'a SamplingContentBlock,
    ) -> SamplingHostFuture<'a, SamplingContentBlock> {
        self.check(cx);
        self.calls.push("tool");
        let SamplingContentBlock::ToolUse { id, .. } = call else {
            panic!("not a tool call")
        };
        Box::pin(async move {
            self.check(cx);
            Ok(serde_json::from_value(json!({
                "type":"tool_result","toolUseId":id,
                "content":[{"type":"text","text":"answer"}]
            }))
            .unwrap())
        })
    }

    fn parallel_tools(&self) -> Option<parallel::ParallelSamplingTools<'_>> {
        assert_eq!(row(&Cx::current().unwrap()), self.expected);
        self.parallel_hooks.fetch_add(1, Ordering::SeqCst);
        None
    }
}

#[test]
fn public_model_approval_tool_and_parallel_hook_preserve_every_effect_ceiling() {
    runtime(|cx, timer| {
        for ambient_bits in 0..=ALL {
            for explicit_bits in [ALL, ALL & !16] {
                let caller = held(cx, explicit_bits);
                let ambient = held(&Cx::for_testing(), ambient_bits);
                let expected = explicit_bits & ambient_bits;
                let cancellation = McpRequestCancellation::new();
                let mut host = Host::new(expected);
                let mut run = Box::pin(run_sampling_tool_loop(
                    &caller,
                    &cancellation,
                    request(),
                    SamplingRunLimits::default(),
                    &mut host,
                ));
                let mut outcome = None;
                for _ in 0..32 {
                    let _ambient = Cx::set_current(Some(ambient.clone()));
                    let depth = Cx::restriction_depth();
                    let polled = run.as_mut().poll(&mut Context::from_waker(Waker::noop()));
                    assert_eq!(row(&Cx::current().unwrap()), ambient_bits);
                    assert_eq!(Cx::restriction_depth(), depth);
                    if let Poll::Ready(result) = polled {
                        outcome = Some(result);
                        break;
                    }
                }
                drop(run);
                let outcome = outcome.expect("finite local host must settle");
                if expected & TIME == 0 {
                    assert!(matches!(outcome, Err(SamplingRunError::RuntimeUnavailable)));
                    assert!(host.calls.is_empty());
                    assert_eq!(host.parallel_hooks.load(Ordering::SeqCst), 0);
                } else {
                    let result = outcome.unwrap();
                    assert_eq!(result.model_rounds, 2);
                    assert_eq!(result.executed_tools, 1);
                    assert_eq!(host.calls, ["model", "approve", "tool", "model"]);
                    assert_eq!(host.parallel_hooks.load(Ordering::SeqCst), 1);
                }
                assert!(!cancellation.is_cancel_requested());
                assert!(!caller.is_cancel_requested());
                assert_eq!(timer.pending_count(), 0);
            }
        }
    });
}

#[test]
fn a_pending_wait_reads_the_new_ambient_ceiling_on_each_poll() {
    runtime(|cx, timer| {
        let cancellation = McpRequestCancellation::new();
        let end = cx.now().saturating_add_nanos(10_000_000_000);
        let mut observed = Vec::new();
        let mut future = Box::pin(within(cx, &cancellation, end, poll_fn(|_| {
            observed.push(row(&Cx::current().unwrap()));
            if observed.len() == 3 {
                Poll::Ready(Ok(42))
            } else {
                Poll::Pending
            }
        })));
        for (index, bits) in [ALL & !8, ALL & !4, ALL & !1 & !16]
            .into_iter()
            .enumerate()
        {
            let ambient = held(&Cx::for_testing(), bits);
            let _ambient = Cx::set_current(Some(ambient));
            let depth = Cx::restriction_depth();
            let outcome = future.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            assert_eq!(
                outcome,
                if index == 2 {
                    Poll::Ready(Ok(42))
                } else {
                    Poll::Pending
                }
            );
            assert_eq!(row(&Cx::current().unwrap()), bits);
            assert_eq!(Cx::restriction_depth(), depth);
        }
        drop(future);
        assert_eq!(observed, [ALL & !8, ALL & !4, ALL & !1 & !16]);
        assert_eq!(timer.pending_count(), 0);
    });
}

#[test]
fn withdrawing_time_permission_retires_quiet_work_without_another_child_poll() {
    runtime(|cx, timer| {
        let cancellation = McpRequestCancellation::new();
        let end = cx.now().saturating_add_nanos(10_000_000_000);
        let polls = AtomicUsize::new(0);
        let drops = Arc::new(AtomicUsize::new(0));
        struct Owned(Arc<AtomicUsize>);
        impl Drop for Owned {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let owned = Owned(Arc::clone(&drops));
        let mut future = Box::pin(within(cx, &cancellation, end, async {
            let _owned = owned;
            poll_fn(|_| {
                polls.fetch_add(1, Ordering::SeqCst);
                Poll::<Result<(), SamplingRunError>>::Pending
            })
            .await
        }));
        assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(timer.pending_count(), 1);
        let denied = held(&Cx::for_testing(), ALL & !TIME);
        let _ambient = Cx::set_current(Some(denied));
        assert_eq!(
            future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(SamplingRunError::RuntimeUnavailable))
        );
        drop(future);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(timer.pending_count(), 0);
        assert!(!cx.is_cancel_requested());
    });
}

#[test]
fn a_panicking_model_callback_cannot_leave_a_wider_context_installed() {
    runtime(|cx, timer| {
        let cancellation = McpRequestCancellation::new();
        let mut host = Host::new(ALL & !8);
        host.panic_in_model = true;
        let mut run = Box::pin(run_sampling_tool_loop(
            cx,
            &cancellation,
            request(),
            SamplingRunLimits::default(),
            &mut host,
        ));
        let ambient = held(&Cx::for_testing(), ALL & !8);
        let _ambient = Cx::set_current(Some(ambient));
        let depth = Cx::restriction_depth();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = run.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        }))
        .is_err());
        drop(run);
        assert_eq!(host.calls, ["model"]);
        assert_eq!(row(&Cx::current().unwrap()), ALL & !8);
        assert_eq!(Cx::restriction_depth(), depth);
        assert_eq!(timer.pending_count(), 0);
        assert!(!cancellation.is_cancel_requested());
    });
}
