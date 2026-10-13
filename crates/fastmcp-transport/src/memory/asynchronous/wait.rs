//! Wake-driven lifetime observation for memory-channel operations.

use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::task::Poll;

use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
use asupersync::time::Sleep;
use asupersync::{Cx, channel::oneshot};

use crate::TransportError;

// Capture the host's effect ceiling BEFORE installing the explicit caller.
// set_current preserves the supplied context's own mask, not the narrower
// ambient view it replaces. This is the same intersection used by native
// stdio and request-region admission. The host contributes only restrictions,
// never its identity, cancellation state, clock, deadline or timer driver.
fn ambient_capability_ceiling() -> CapMask {
    let Some(active) = Cx::current() else {
        return CapMask::all();
    };
    let capabilities = active.capabilities();
    let mut ceiling = CapMask::all();
    for (allowed, without_effect) in [
        (
            capabilities.spawn,
            CapSet::<false, true, true, true, true>::MASK,
        ),
        (
            capabilities.time,
            CapSet::<true, false, true, true, true>::MASK,
        ),
        (
            capabilities.entropy,
            CapSet::<true, true, false, true, true>::MASK,
        ),
        (
            capabilities.io,
            CapSet::<true, true, true, false, true>::MASK,
        ),
        (
            capabilities.remote,
            CapSet::<true, true, true, true, false>::MASK,
        ),
    ] {
        if !allowed {
            ceiling = ceiling.intersect(without_effect);
        }
    }
    ceiling
}

/// Register cancellation independently of channel readiness. The channel future
/// still owns its FIFO waiter and checked send obligation; dropping it rolls
/// those back. Nothing polls cancellation after publication or dequeue succeeds.
/// Pending operations also register the caller's deadline with its timer driver:
/// a checkpoint alone cannot wake a task parked on an idle or full channel.
/// Binding that driver must not restore effects relinquished by the host scope.
pub(super) async fn await_channel<T>(
    cx: &Cx,
    operation: impl Future<Output = Result<T, TransportError>>,
) -> Result<T, TransportError> {
    // Never publish on this channel. Its receiver supplies the public Cx
    // cancellation registration, and its sender lives until this wait ends.
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = pin!(receiver.recv(cx));
    let mut operation = pin!(operation);
    let mut deadline_timer: Option<Sleep> = None;
    let mut deadline_observed = false;
    poll_fn(|task| {
        // Re-evaluate the host ceiling on every poll: a suspended operation
        // can resume in a narrower scope. Both guards unwind before yielding.
        // Sleep still resolves the explicit caller's driver, not the host's.
        let ceiling = ambient_capability_ceiling();
        let _caller = Cx::set_current(Some(cx.clone()));
        let _restriction = Cx::push_restriction(ceiling);
        if cx.checkpoint().is_err() {
            return Poll::Ready(Err(TransportError::Cancelled));
        }
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(TransportError::Cancelled));
        }
        // Ready is the commitment boundary, even if the operation's wake
        // callback cancelled the context or advanced its clock while publishing
        // its message. In particular, timer admission cannot undo a dequeue.
        if let Poll::Ready(result) = operation.as_mut().poll(task) {
            return Poll::Ready(result);
        }
        if !deadline_observed && let Some(deadline) = cx.budget().deadline {
            // Only a pending operation needs a timer. This preserves immediately
            // ready operations on driverless contexts, including masked cleanup,
            // without silently parking a bounded wait that cannot be woken.
            // Check authority separately from driver availability: a retained
            // driver is not permission to use it under a narrower host scope.
            if !ceiling.contains(CapSet::<false, true, false, false, false>::MASK)
                || !cx.capabilities().time
            {
                return Poll::Ready(Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "pending memory transport deadline requires the time capability",
                ))));
            }
            if cx.timer_driver().is_none() {
                return Poll::Ready(Err(TransportError::Io(std::io::Error::other(
                    "pending memory transport deadline requires an asupersync timer driver",
                ))));
            }
            let timer = deadline_timer.get_or_insert_with(|| Sleep::new(deadline));
            if Pin::new(timer).poll(task).is_ready() {
                deadline_observed = true;
                // The deadline can elapse during the operation's Pending poll.
                // Keep the channel's checkpoint/masking contract rather than
                // turning a masked deadline into an unconditional timeout.
                if cx.checkpoint().is_err() {
                    return Poll::Ready(Err(TransportError::Cancelled));
                }
                // Under a mask, continue waiting for channel readiness. Do not
                // poll a completed timer again or self-wake in a busy loop.
            }
        }
        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};
    use std::time::Duration;

    use asupersync::runtime::RuntimeBuilder;
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use asupersync::{Budget, Time};
    use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest};

    use crate::Transport;
    use crate::memory::create_memory_transport_pair_with_capacity;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(waker))
    }

    fn ready<F: Future>(future: F) -> F::Output {
        match poll(pin!(future), Waker::noop()) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("in-memory operation unexpectedly waited"),
        }
    }

    fn request(id: i64) -> JsonRpcMessage {
        JsonRpcMessage::Request(JsonRpcRequest::new("test/wake", None, id))
    }

    /// JSON-RPC messages have no `PartialEq`; compare what they serialize to.
    fn json(message: &JsonRpcMessage) -> serde_json::Value {
        serde_json::to_value(message).expect("a JSON-RPC message serializes")
    }

    fn with_deadline(test: impl FnOnce(&Cx, &Arc<VirtualClock>, &TimerDriverHandle)) {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let cx = runtime
            .request_cx_with_budget(Budget::INFINITE.with_deadline(Time::from_nanos(10_000_000)));
        test(&cx, &clock, &timer);
        assert_eq!(timer.pending_count(), 0);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn cancellation_wakes_idle_receive_without_peer_activity() {
        let (mut client, mut server) = create_memory_transport_pair_with_capacity(1);
        let cx = Cx::for_testing();
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        {
            let mut receiving = pin!(server.recv_with_source_async(&cx));
            assert!(poll(receiving.as_mut(), &waker).is_pending());
            let before = wakes.0.load(Ordering::SeqCst);
            cx.set_cancel_requested(true);
            // Assert the wake BEFORE manually polling again. A checkpoint on
            // the next poll alone cannot wake an executor parked on an idle peer.
            assert!(wakes.0.load(Ordering::SeqCst) > before);
            assert!(matches!(
                poll(receiving.as_mut(), &waker),
                Poll::Ready(Err(TransportError::Cancelled))
            ));
        }
        assert!(!server.is_closed());
        let live = Cx::for_testing();
        client.send(&live, &request(1)).unwrap();
        assert_eq!(
            json(&ready(server.recv_async(&live)).unwrap()),
            json(&request(1))
        );
    }

    #[test]
    fn cancellation_wakes_full_queue_send_without_peer_drain() {
        let (mut client, mut server) = create_memory_transport_pair_with_capacity(1);
        let live = Cx::for_testing();
        let cx = Cx::for_testing();
        client.send(&live, &request(1)).unwrap();
        let second = request(2);
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        {
            let mut sending = pin!(client.send_async(&cx, &second));
            assert!(poll(sending.as_mut(), &waker).is_pending());
            let before = wakes.0.load(Ordering::SeqCst);
            cx.set_cancel_requested(true);
            assert!(wakes.0.load(Ordering::SeqCst) > before);
            assert!(matches!(
                poll(sending.as_mut(), &waker),
                Poll::Ready(Err(TransportError::Cancelled))
            ));
        }
        assert!(!client.is_closed());
        assert_eq!(json(&server.recv(&live).unwrap()), json(&request(1)));
        ready(client.send_async(&live, &request(3))).unwrap();
        assert_eq!(json(&server.recv(&live).unwrap()), json(&request(3)));
    }

    #[test]
    fn cancellation_wakes_reservation_without_leaking_capacity() {
        let (mut client, mut server) = create_memory_transport_pair_with_capacity(1);
        let live = Cx::for_testing();
        let cx = Cx::for_testing();
        client.send(&live, &request(1)).unwrap();
        let (_recv, mut send) = client.into_split();
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        {
            let mut reserving = pin!(send.reserve_send_async(&cx));
            assert!(poll(reserving.as_mut(), &waker).is_pending());
            let before = wakes.0.load(Ordering::SeqCst);
            cx.set_cancel_requested(true);
            assert!(wakes.0.load(Ordering::SeqCst) > before);
            assert!(matches!(
                poll(reserving.as_mut(), &waker),
                Poll::Ready(Err(TransportError::Cancelled))
            ));
        }
        assert!(!send.is_closed());
        assert_eq!(json(&server.recv(&live).unwrap()), json(&request(1)));
        ready(send.reserve_send_async(&live))
            .unwrap()
            .send(&request(3))
            .unwrap();
        assert_eq!(json(&server.recv(&live).unwrap()), json(&request(3)));
    }

    #[test]
    fn dropped_wait_unregisters_its_cancellation_waker() {
        let (_client, mut server) = create_memory_transport_pair_with_capacity(1);
        let cx = Cx::for_testing();
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        {
            let mut receiving = pin!(server.recv_async(&cx));
            assert!(poll(receiving.as_mut(), &waker).is_pending());
        }
        let before = wakes.0.load(Ordering::SeqCst);
        cx.set_cancel_requested(true);
        assert_eq!(wakes.0.load(Ordering::SeqCst), before);
    }

    #[test]
    fn successful_operation_is_not_reclassified_after_cancellation() {
        let cx = Cx::for_testing();
        let result = ready(await_channel(&cx, async {
            cx.set_cancel_requested(true);
            Ok(42)
        }));
        assert_eq!(result.unwrap(), 42);
        assert!(cx.checkpoint().is_err());
    }

    #[test]
    fn deadline_wakes_idle_receive_and_preserves_a_late_frame() {
        with_deadline(|cx, clock, timer| {
            let (mut client, mut server) = create_memory_transport_pair_with_capacity(1);
            let live = Cx::for_testing();
            let wakes = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&wakes));
            {
                let mut receiving = pin!(server.recv_with_source_async(cx));
                assert!(poll(receiving.as_mut(), &waker).is_pending());
                assert!(timer.pending_count() > 0);
                clock.advance(9_999_999);
                assert_eq!(timer.process_timers(), 0);
                assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
                clock.advance(1);
                assert!(timer.process_timers() > 0);
                // No peer activity or manual repoll is needed for this wake.
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                client.send(&live, &request(10)).unwrap();
                assert!(matches!(
                    poll(receiving.as_mut(), &waker),
                    Poll::Ready(Err(TransportError::Cancelled))
                ));
            }
            assert!(!server.is_closed());
            assert_eq!(
                json(&ready(server.recv_async(&live)).unwrap()),
                json(&request(10))
            );
        });
    }

    #[test]
    fn deadline_wakes_backpressured_sends_and_reservations_without_peer_drain() {
        for reserve in [false, true] {
            with_deadline(|cx, clock, timer| {
                let (mut client, mut server) = create_memory_transport_pair_with_capacity(1);
                let live = Cx::for_testing();
                client.send(&live, &request(11)).unwrap();
                let (_recv, mut send) = client.into_split();
                let message = request(12);
                let wakes = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&wakes));
                {
                    let mut sending = pin!(async {
                        if reserve {
                            send.reserve_send_async(cx).await?.send(&message)
                        } else {
                            send.send_async(cx, &message).await
                        }
                    });
                    assert!(poll(sending.as_mut(), &waker).is_pending());
                    assert!(timer.pending_count() > 0);
                    let before = wakes.0.load(Ordering::SeqCst);
                    clock.advance(10_000_000);
                    assert!(timer.process_timers() > 0);
                    assert!(wakes.0.load(Ordering::SeqCst) > before);
                    assert!(matches!(
                        poll(sending.as_mut(), &waker),
                        Poll::Ready(Err(TransportError::Cancelled))
                    ));
                }
                assert!(!send.is_closed());
                assert_eq!(json(&server.recv(&live).unwrap()), json(&request(11)));
                // The cancelled operation neither published its frame nor kept
                // a reservation that would prevent the next sender progressing.
                ready(send.reserve_send_async(&live))
                    .unwrap()
                    .send(&request(13))
                    .unwrap();
                assert_eq!(json(&server.recv(&live).unwrap()), json(&request(13)));
            });
        }
    }

    #[test]
    fn dropping_pending_receive_retires_deadline_and_cancellation_registrations() {
        with_deadline(|cx, clock, timer| {
            let (mut client, mut server) = create_memory_transport_pair_with_capacity(1);
            let wakes = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&wakes));
            {
                let mut receiving = pin!(server.recv_async(cx));
                assert!(poll(receiving.as_mut(), &waker).is_pending());
                assert!(timer.pending_count() > 0);
            }
            assert_eq!(timer.pending_count(), 0);
            let before = wakes.0.load(Ordering::SeqCst);
            clock.advance(10_000_000);
            assert_eq!(timer.process_timers(), 0);
            cx.set_cancel_requested(true);
            assert_eq!(wakes.0.load(Ordering::SeqCst), before);
            let live = Cx::for_testing();
            client.send(&live, &request(14)).unwrap();
            assert_eq!(
                json(&ready(server.recv_async(&live)).unwrap()),
                json(&request(14))
            );
        });
    }

    #[test]
    fn deadline_during_poll_refuses_pending_work_but_preserves_ready_commit() {
        for committed in [false, true] {
            with_deadline(|cx, clock, _timer| {
                let polls = AtomicUsize::new(0);
                let operation = poll_fn(|_| {
                    polls.fetch_add(1, Ordering::SeqCst);
                    clock.advance(10_000_000);
                    if committed {
                        Poll::Ready(Ok(42))
                    } else {
                        Poll::Pending
                    }
                });
                let result = ready(await_channel(cx, operation));
                if committed {
                    assert_eq!(result.unwrap(), 42);
                } else {
                    assert!(matches!(result, Err(TransportError::Cancelled)));
                }
                assert_eq!(polls.load(Ordering::SeqCst), 1);
            });
        }
    }

    #[test]
    fn driverless_deadlines_allow_ready_operations_but_refuse_pending_waits() {
        for pending in [false, true] {
            let cx = Cx::for_testing_with_budget(
                Budget::INFINITE.with_deadline(Time::from_nanos(u64::MAX)),
            );
            assert!(cx.timer_driver().is_none());
            let polls = AtomicUsize::new(0);
            let result = ready(await_channel(
                &cx,
                poll_fn(|_| {
                    polls.fetch_add(1, Ordering::SeqCst);
                    if pending {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(42))
                    }
                }),
            ));
            if pending {
                let Err(TransportError::Io(error)) = result else {
                    panic!("a driverless deadline must not park a pending wait");
                };
                assert!(error.to_string().contains("timer driver"));
            } else {
                assert_eq!(result.unwrap(), 42);
            }
            assert_eq!(polls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn masked_expired_deadline_does_not_override_ready_channel_work() {
        let cx = Cx::for_testing_with_budget(Budget::INFINITE.with_deadline(Time::ZERO));
        let (mut client, mut server) = create_memory_transport_pair_with_capacity(1);
        let live = Cx::for_testing();
        client.send(&live, &request(15)).unwrap();
        assert!(matches!(
            ready(server.recv_async(&cx)),
            Err(TransportError::Cancelled)
        ));
        let frame = cx.masked(|| ready(server.recv_async(&cx)).unwrap());
        assert_eq!(json(&frame), json(&request(15)));
        assert!(!server.is_closed());
    }

    #[test]
    fn deadline_timer_uses_the_callers_driver_not_the_ambient_runtime() {
        with_deadline(|cx, clock, timer| {
            let foreign_clock = Arc::new(VirtualClock::new());
            foreign_clock.advance(1_000_000_000);
            let foreign_timer = TimerDriverHandle::with_virtual_clock(foreign_clock);
            let foreign_runtime = RuntimeBuilder::current_thread()
                .blocking_threads(0, 0)
                .with_timer_driver(foreign_timer.clone())
                .build()
                .unwrap();
            let foreign_cx = foreign_runtime.request_cx_with_budget(Budget::INFINITE);
            let ambient = Cx::set_current(Some(foreign_cx.clone()));
            let (_client, mut server) = create_memory_transport_pair_with_capacity(1);
            let wakes = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&wakes));
            {
                let mut receiving = pin!(server.recv_async(cx));
                assert!(poll(receiving.as_mut(), &waker).is_pending());
                assert!(timer.pending_count() > 0);
                assert_eq!(foreign_timer.pending_count(), 0);
                assert_eq!(Cx::current().unwrap().now(), foreign_cx.now());
                clock.advance(10_000_000);
                assert!(timer.process_timers() > 0);
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                assert!(matches!(
                    poll(receiving.as_mut(), &waker),
                    Poll::Ready(Err(TransportError::Cancelled))
                ));
            }
            assert_eq!(foreign_timer.pending_count(), 0);
            assert_eq!(Cx::current().unwrap().now(), foreign_cx.now());
            assert!(!foreign_cx.is_cancel_requested());
            drop(ambient);
            drop(foreign_cx);
            assert!(foreign_runtime.shutdown_timeout(Duration::from_secs(1)));
        });
    }

    mod authority {
        use super::*;

        fn effects(cx: &Cx) -> [bool; 5] {
            let row = cx.capabilities();
            [row.spawn, row.time, row.entropy, row.io, row.remote]
        }

        fn rows() -> [(CapMask, [bool; 5]); 7] {
            [
                (CapMask::all(), [true; 5]),
                (CapMask::none(), [false; 5]),
                (CapSet::<false, true, true, true, true>::MASK, [false, true, true, true, true]),
                (CapSet::<true, false, true, true, true>::MASK, [true, false, true, true, true]),
                (CapSet::<true, true, false, true, true>::MASK, [true, true, false, true, true]),
                (CapSet::<true, true, true, false, true>::MASK, [true, true, true, false, true]),
                (CapSet::<true, true, true, true, false>::MASK, [true, true, true, true, false]),
            ]
        }

        fn scoped<T>(cx: &Cx, mask: CapMask, operation: impl FnOnce() -> T) -> T {
            let _caller = Cx::set_current(Some(cx.clone()));
            let _restriction = Cx::push_restriction(mask);
            operation()
        }

        fn no_time() -> CapMask {
            CapSet::<true, false, true, true, true>::MASK
        }

        fn denied(result: Result<(), TransportError>) {
            let Err(TransportError::Io(error)) = result else {
                panic!("a pending deadline without time authority must be refused");
            };
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        }

        #[test]
        fn channel_poll_intersects_every_caller_and_host_effect_dimension() {
            for (caller_mask, caller_effects) in rows() {
                let caller = scoped(&Cx::for_testing(), caller_mask, || Cx::current().unwrap());
                for (host_mask, host_effects) in rows() {
                    let host = Cx::for_testing();
                    scoped(&host, host_mask, || {
                        let actual = ready(await_channel(&caller, async {
                            Ok(effects(&Cx::current().unwrap()))
                        })).unwrap();
                        let expected = std::array::from_fn(|index| {
                            caller_effects[index] && host_effects[index]
                        });
                        assert_eq!(actual, expected);
                        assert_eq!(effects(&Cx::current().unwrap()), host_effects);
                    });
                }
            }
        }

        #[test]
        fn resumed_channel_wait_rechecks_host_scope_without_leaking_it() {
            let caller = Cx::for_testing();
            let host = Cx::for_testing();
            let observed = std::cell::RefCell::new(Vec::new());
            {
                let mut waiting = pin!(await_channel(&caller, poll_fn(|_| {
                    observed.borrow_mut().push(effects(&Cx::current().unwrap()));
                    Poll::<Result<(), TransportError>>::Pending
                })));
                for (mask, expected) in rows() {
                    scoped(&host, mask, || {
                        assert!(poll(waiting.as_mut(), Waker::noop()).is_pending());
                        assert_eq!(observed.borrow().last(), Some(&expected));
                        assert_eq!(effects(&Cx::current().unwrap()), expected);
                    });
                }
            }
            assert_eq!(observed.borrow().len(), 7);
            assert_eq!(effects(&caller), [true; 5]);
            assert!(caller.checkpoint().is_ok());
        }

        #[test]
        fn pending_receive_send_and_reservation_refuse_missing_time_authority_without_leaks() {
            for held_restriction in [false, true] {
                for operation in 0..3 {
                    with_deadline(|cx, _clock, timer| {
                        let caller = if held_restriction {
                            scoped(cx, no_time(), || Cx::current().unwrap())
                        } else {
                            cx.clone()
                        };
                        let (mut client, mut server) = create_memory_transport_pair_with_capacity(1);
                        let live = Cx::for_testing();
                        if operation != 0 {
                            client.send(&live, &request(61)).unwrap();
                        }
                        let mask = if held_restriction { CapMask::all() } else { no_time() };
                        let result = scoped(cx, mask, || match operation {
                            0 => ready(server.recv_async(&caller)).map(|_| ()),
                            1 => ready(client.send_async(&caller, &request(62))),
                            2 => ready(client.reserve_send_async(&caller)).map(|permit| permit.abort()),
                            _ => unreachable!(),
                        });
                        denied(result);
                        assert_eq!(timer.pending_count(), 0);
                        assert!(!client.is_closed() && !server.is_closed());
                        if operation != 0 {
                            assert_eq!(json(&server.recv(&live).unwrap()), json(&request(61)));
                        }
                        // Neither a failed receive nor a blocked producer may
                        // keep capacity, publish its rejected frame or poison
                        // the next call made under a live, admitted context.
                        ready(client.send_async(&live, &request(63))).unwrap();
                        assert_eq!(json(&ready(server.recv_async(&live)).unwrap()), json(&request(63)));
                    });
                }
            }
        }

        #[test]
        fn ready_channel_commit_does_not_require_unused_timer_authority() {
            for operation in 0..3 {
                with_deadline(|cx, _clock, timer| {
                    let (mut client, mut server) = create_memory_transport_pair_with_capacity(1);
                    let live = Cx::for_testing();
                    if operation == 0 {
                        client.send(&live, &request(71)).unwrap();
                    }
                    scoped(cx, no_time(), || {
                        match operation {
                            0 => assert_eq!(json(&ready(server.recv_async(cx)).unwrap()), json(&request(71))),
                            1 => ready(client.send_async(cx, &request(71))).unwrap(),
                            2 => ready(client.reserve_send_async(cx)).unwrap().send(&request(71)).unwrap(),
                            _ => unreachable!(),
                        }
                    });
                    assert_eq!(timer.pending_count(), 0);
                    if operation != 0 {
                        assert_eq!(json(&server.recv(&live).unwrap()), json(&request(71)));
                    }
                    assert!(!client.is_closed() && !server.is_closed());
                });
            }
        }

        #[test]
        fn narrowing_a_pending_wait_retires_its_timer_and_cancellation_waker() {
            with_deadline(|cx, clock, timer| {
                let (mut client, mut server) = create_memory_transport_pair_with_capacity(1);
                let wakes = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&wakes));
                {
                    let mut receiving = pin!(server.recv_async(cx));
                    scoped(cx, CapMask::all(), || {
                        assert!(poll(receiving.as_mut(), &waker).is_pending());
                    });
                    assert!(timer.pending_count() > 0);
                    scoped(cx, no_time(), || {
                        let Poll::Ready(result) = poll(receiving.as_mut(), &waker) else {
                            panic!("the retained driver must not bypass a narrower host");
                        };
                        denied(result.map(|_| ()));
                    });
                    // Completion, not later parent shutdown, retires observers.
                    assert_eq!(timer.pending_count(), 0);
                }
                let before = wakes.0.load(Ordering::SeqCst);
                clock.advance(10_000_000);
                assert_eq!(timer.process_timers(), 0);
                cx.set_cancel_requested(true);
                assert_eq!(wakes.0.load(Ordering::SeqCst), before);
                let live = Cx::for_testing();
                client.send(&live, &request(81)).unwrap();
                assert_eq!(json(&ready(server.recv_async(&live)).unwrap()), json(&request(81)));
            });
        }

        #[test]
        fn stopped_host_contributes_restrictions_not_a_replacement_lifetime() {
            with_deadline(|cx, _clock, timer| {
                let host = Cx::for_testing_with_budget(Budget::INFINITE.with_deadline(Time::ZERO));
                host.set_cancel_requested(true);
                let (mut client, mut server) = create_memory_transport_pair_with_capacity(1);
                let live = Cx::for_testing();
                let mask = CapSet::<true, true, true, false, true>::MASK;
                {
                    let mut receiving = pin!(server.recv_async(cx));
                    scoped(&host, mask, || {
                        assert!(poll(receiving.as_mut(), Waker::noop()).is_pending());
                        assert!(!Cx::current().unwrap().capabilities().io);
                    });
                    assert!(timer.pending_count() > 0);
                    assert!(!cx.is_cancel_requested());
                    client.send(&live, &request(91)).unwrap();
                    scoped(&host, mask, || {
                        let Poll::Ready(Ok(frame)) = poll(receiving.as_mut(), Waker::noop()) else {
                            panic!("a stopped foreign host must not cancel the live caller");
                        };
                        assert_eq!(json(&frame), json(&request(91)));
                    });
                }
                assert_eq!(timer.pending_count(), 0);
                assert!(host.checkpoint().is_err());
                assert!(cx.checkpoint().is_ok());
            });
        }

        #[test]
        fn deadline_free_memory_wait_progresses_with_all_host_effects_disabled() {
            let caller = Cx::for_testing();
            let host = Cx::for_testing();
            let (mut client, mut server) = create_memory_transport_pair_with_capacity(1);
            let wakes = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut receiving = pin!(server.recv_async(&caller));
            scoped(&host, CapMask::none(), || {
                assert!(poll(receiving.as_mut(), &waker).is_pending());
            });
            client.send(&caller, &request(101)).unwrap();
            assert!(wakes.0.load(Ordering::SeqCst) > 0);
            scoped(&host, CapMask::none(), || {
                let Poll::Ready(Ok(frame)) = poll(receiving.as_mut(), &waker) else {
                    panic!("local channel progress needs no spawn, timer or I/O driver");
                };
                assert_eq!(json(&frame), json(&request(101)));
                assert_eq!(effects(&Cx::current().unwrap()), [false; 5]);
            });
        }
    }
}
