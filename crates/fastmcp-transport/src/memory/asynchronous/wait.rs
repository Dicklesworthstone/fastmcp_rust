//! Wake-driven lifetime observation for memory-channel operations.

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;

use asupersync::{Cx, channel::oneshot};

use crate::TransportError;

/// Register cancellation independently of channel readiness. The channel future
/// still owns its FIFO waiter and checked send obligation; dropping it rolls
/// those back. Nothing polls cancellation after publication or dequeue succeeds.
pub(super) async fn await_channel<T>(
    cx: &Cx,
    operation: impl Future<Output = Result<T, TransportError>>,
) -> Result<T, TransportError> {
    // Never publish on this channel. Its receiver supplies the public Cx
    // cancellation registration, and its sender lives until this wait ends.
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = pin!(receiver.recv(cx));
    let mut operation = pin!(operation);
    poll_fn(|task| {
        let _caller = Cx::set_current(Some(cx.clone()));
        if cx.checkpoint().is_err() {
            return Poll::Ready(Err(TransportError::Cancelled));
        }
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(TransportError::Cancelled));
        }
        // Ready is the commitment boundary, even if the operation's wake
        // callback cancelled the context while publishing its message.
        operation.as_mut().poll(task)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

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
}
