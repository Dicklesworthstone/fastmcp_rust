//! Wake-driven lifetime observation for memory-channel operations.

use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::task::Poll;

use asupersync::time::Sleep;
use asupersync::{Cx, channel::oneshot};

use crate::TransportError;

/// Register cancellation independently of channel readiness. The channel future
/// still owns its FIFO waiter and checked send obligation; dropping it rolls
/// those back. Nothing polls cancellation after publication or dequeue succeeds.
/// Pending operations also register the caller's deadline with its timer driver:
/// a checkpoint alone cannot wake a task parked on an idle or full channel.
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
        // Sleep resolves its driver during polling. Keep both the operation
        // and its timer on the supplied caller, never an unrelated ambient Cx.
        let _caller = Cx::set_current(Some(cx.clone()));
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
}
