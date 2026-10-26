//! Caller-budget boundary for the entire native connection and TLS close.
//!
//! Request-read and per-frame write timeouts do not cover a JSON handler wait,
//! an idle SSE response, or a cleanup operation started near the caller's
//! deadline. Drive one owned future under the existing cancellation/deadline
//! guard, retaining it across every wake. Dropping it invokes the native
//! response/session owners; no detached task or second cleanup owner is created.

use std::future::Future;
use std::sync::{Arc, Mutex, atomic::Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::time::Sleep;
use fastmcp_core::McpRequestCancellation;

use super::super::{SecuredHttpEndpointError, await_dispatch};
use crate::{
    FINAL_TERMINAL_DRAINED, FINAL_TERMINAL_ENQUEUED, FINAL_TERMINAL_FAILED,
    FinalSubscriptionTerminalDelivery, HTTP_TERMINAL_DRAIN_TIMEOUT, HttpListenerShutdown,
    ModernSseOutcomeGate,
};

pub(super) async fn drive<T>(
    cx: &Cx,
    operation: impl Future<Output = T>,
) -> Result<T, SecuredHttpEndpointError> {
    await_dispatch(cx, async { Ok(operation.await) }).await
}

/// Only an admitted subscription can retain its native connection through
/// listener shutdown. This slot shares the existing dispatch election and
/// terminal receipt; it neither copies authorization nor creates a new grant.
#[derive(Default)]
pub(super) struct SubscriptionDrain {
    owner: Mutex<Option<SubscriptionDrainOwner>>,
}

struct SubscriptionDrainOwner {
    cancellation: McpRequestCancellation,
    terminal: Arc<FinalSubscriptionTerminalDelivery>,
    admission: Arc<ModernSseOutcomeGate>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectionPoll {
    Live,
    AwaitingTerminal,
    Terminal,
}

impl SubscriptionDrain {
    pub(super) fn register(
        &self,
        cancellation: McpRequestCancellation,
        terminal: Arc<FinalSubscriptionTerminalDelivery>,
        admission: Arc<ModernSseOutcomeGate>,
    ) {
        *self.owner.lock().unwrap() = Some(SubscriptionDrainOwner {
            cancellation,
            terminal,
            admission,
        });
    }

    fn authority(
        &self,
        cx: &Cx,
        shutdown: &HttpListenerShutdown,
    ) -> Result<ConnectionPoll, SecuredHttpEndpointError> {
        let stopping = shutdown.is_requested();
        let cancelled = cx.checkpoint().is_err();
        // Cancellation of this connection alone is never listener authority.
        if cancelled && !stopping {
            return Err(SecuredHttpEndpointError::Cancelled);
        }
        let owner = self.owner.lock().unwrap();
        if let Some(owner) = owner.as_ref()
            && owner.admission.stream_admitted()
        {
            let control = owner.terminal.state.load(Ordering::Acquire);
            let completion = owner.terminal.completion_state.load(Ordering::Acquire);
            if control == FINAL_TERMINAL_FAILED || completion == FINAL_TERMINAL_FAILED {
                return Err(SecuredHttpEndpointError::Cancelled);
            }
            if matches!(control, FINAL_TERMINAL_ENQUEUED | FINAL_TERMINAL_DRAINED)
                && completion == FINAL_TERMINAL_DRAINED
            {
                // Transport consumption wakes the request token before the
                // final socket flush. Only this exact elected receipt can
                // retain the write, including its terminating chunk trailer.
                return Ok(ConnectionPoll::Terminal);
            }
            if owner.cancellation.is_cancel_requested() {
                return Err(SecuredHttpEndpointError::Cancelled);
            }
            if stopping {
                return Ok(ConnectionPoll::AwaitingTerminal);
            }
        }
        if stopping || cancelled {
            Err(SecuredHttpEndpointError::Cancelled)
        } else {
            Ok(ConnectionPoll::Live)
        }
    }

    fn fail(&self) {
        let owner = self.owner.lock().unwrap().as_ref().map(|owner| {
            (Arc::clone(&owner.terminal), owner.cancellation.clone())
        });
        if let Some((terminal, cancellation)) = owner {
            terminal.mark_failed();
            cancellation.cancel();
        }
    }
}

impl Drop for SubscriptionDrain {
    fn drop(&mut self) {
        // Dropping a partially driven connection must settle its receipt too.
        // mark_failed cannot replace a control already recorded as drained.
        self.fail();
    }
}

/// Retain one pinned connection through the existing subscription terminal
/// election. The ordinary caller deadline remains absolute; a terminal gets
/// one additional finite drain bound, never a fresh allowance per frame.
pub(super) async fn drive_connection<T>(
    cx: &Cx,
    shutdown: &HttpListenerShutdown,
    subscription: &SubscriptionDrain,
    write_timeout: Duration,
    operation: impl Future<Output = T>,
) -> Result<T, SecuredHttpEndpointError> {
    let caller_deadline = cx.budget().deadline;
    if caller_deadline.is_some() && cx.timer_driver().is_none() {
        return Err(SecuredHttpEndpointError::TimerUnavailable);
    }
    let allowance = write_timeout.min(HTTP_TERMINAL_DRAIN_TIMEOUT);
    let mut drain_deadline = None;
    let mut authority = || {
        if caller_deadline.is_some_and(|deadline| cx.now() >= deadline) {
            return Err(SecuredHttpEndpointError::TimedOut);
        }
        let permit = subscription.authority(cx, shutdown)?;
        if permit != ConnectionPoll::Live {
            let (deadline, started) = drain_deadline.get_or_insert_with(|| {
                (
                    cx.now().saturating_add_nanos(
                        u64::try_from(allowance.as_nanos()).unwrap_or(u64::MAX),
                    ),
                    Instant::now(),
                )
            });
            if cx.now() >= *deadline || started.elapsed() >= allowance {
                return Err(SecuredHttpEndpointError::TimedOut);
            }
        }
        Ok(permit)
    };
    let mut operation = std::pin::pin!(operation);
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancellation_wake = std::pin::pin!(receiver.recv(cx));
    let mut wake = Box::pin(Sleep::new(cx.now().saturating_add_nanos(10_000_000)));
    let result = async {
        loop {
            let next = std::future::poll_fn(|task| {
                let _current = Cx::set_current(Some(cx.clone()));
                let permit = authority()?;
                if permit == ConnectionPoll::AwaitingTerminal {
                    // Do not call the irreversible authorization guard before
                    // the listener publishes its election. No bytes or auth
                    // work are polled while this exact owner is parked.
                    return Poll::Ready(Ok(None));
                }
                if !cx.is_cancel_requested() {
                    let _ = cancellation_wake.as_mut().poll(task);
                }
                let result = if permit == ConnectionPoll::Terminal {
                    // Mask only this already-elected connection poll. It
                    // includes the native peer read, so ambient cancellation
                    // cannot masquerade as EOF, and the unchanged auth guard
                    // still checks expiry, revocation, facts and scopes.
                    cx.masked(|| operation.as_mut().poll(task))
                } else {
                    operation.as_mut().poll(task)
                };
                if result.is_pending() {
                    // This mask owns only the wake timer, never application
                    // I/O or authentication. Otherwise a concurrent cancel
                    // could complete both an old Sleep and its replacement,
                    // leaving a completed timer to be polled after election.
                    cx.masked(|| {
                        if wake.as_mut().poll(task).is_ready() {
                            wake = Box::pin(Sleep::new(cx.now().saturating_add_nanos(10_000_000)));
                            task.waker().wake_by_ref();
                        }
                    });
                }
                let after = authority()?;
                match result {
                    Poll::Ready(value) if after == ConnectionPoll::AwaitingTerminal => {
                        drop(value);
                        Poll::Ready(Err(SecuredHttpEndpointError::Cancelled))
                    }
                    Poll::Ready(value) => Poll::Ready(Ok(Some(value))),
                    Poll::Pending if after == ConnectionPoll::AwaitingTerminal => {
                        Poll::Ready(Ok(None))
                    }
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?;
            if let Some(value) = next {
                return Ok(value);
            }
            // A cancelled Sleep completes immediately. Yield the bounded
            // election gap so the listener and dispatch can settle instead.
            asupersync::runtime::yield_now().await;
        }
    }
    .await;
    if result.is_err() {
        subscription.fail();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{pending, poll_fn};
    use std::io::{Read, Write};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    use fastmcp_core::McpRequestCancellation;
    use fastmcp_protocol::protocol_policy::ProtocolPolicy;

    use super::super::{
        BoundSecuredHttpServer, SecuredHttpIoLimits, connection, tls::ConnectionIo,
    };
    use crate::http_admission::security::HttpSecurityPolicy;
    use crate::http_admission::{HttpAdmissionLimits, HttpEndpointConfig};
    use crate::{HttpListenerShutdown, Server};

    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Owner(Arc<AtomicUsize>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn subscription_drain(
        admitted: bool,
    ) -> (
        SubscriptionDrain,
        Arc<FinalSubscriptionTerminalDelivery>,
        McpRequestCancellation,
    ) {
        let subscription = SubscriptionDrain::default();
        let terminal = Arc::new(FinalSubscriptionTerminalDelivery::default());
        let cancellation = McpRequestCancellation::new();
        let (admission, _election) = ModernSseOutcomeGate::new();
        if admitted {
            assert!(admission.elect(crate::ModernSseDispatchElection::Stream));
        }
        subscription.register(
            cancellation.clone(),
            Arc::clone(&terminal),
            admission,
        );
        (subscription, terminal, cancellation)
    }

    #[test]
    fn admitted_subscription_parks_then_drains_on_its_original_connection() {
        for cancel_during_poll in [false, true] {
            let cx = Cx::for_testing();
            let sibling = Cx::for_testing();
            let shutdown = HttpListenerShutdown::new(&cx);
            let (subscription, terminal, request) = subscription_drain(true);
            let polls = AtomicUsize::new(0);
            let release = AtomicBool::new(false);
            let operation = poll_fn(|_| {
                let first = polls.fetch_add(1, Ordering::SeqCst) == 0;
                assert!(cx.checkpoint().is_ok(), "only an elected poll may mask shutdown");
                if first && cancel_during_poll {
                    cx.set_cancel_requested(true);
                }
                if release.load(Ordering::Acquire) {
                    assert!(request.is_cancel_requested());
                    terminal.mark_drained();
                    Poll::Ready(37)
                } else {
                    Poll::Pending
                }
            });
            let mut driving = Box::pin(drive_connection(
                &cx,
                &shutdown,
                &subscription,
                Duration::from_secs(1),
                operation,
            ));
            let mut task = Context::from_waker(Waker::noop());
            assert!(driving.as_mut().poll(&mut task).is_pending());
            cx.set_cancel_requested(true);
            for _ in 0..3 {
                assert!(driving.as_mut().poll(&mut task).is_pending());
            }
            assert_eq!(polls.load(Ordering::SeqCst), 1, "parked custody must not poll auth or I/O");
            assert!(!request.is_cancel_requested());
            assert!(terminal.mark_cancellation_enqueued());
            request.cancel();
            assert!(driving.as_mut().poll(&mut task).is_pending());
            assert_eq!(polls.load(Ordering::SeqCst), 2);
            release.store(true, Ordering::Release);
            assert_eq!(driving.as_mut().poll(&mut task), Poll::Ready(Ok(37)));
            assert_eq!(polls.load(Ordering::SeqCst), 3);
            assert!(terminal.is_drained());
            assert!(cx.checkpoint().is_err(), "the elected poll cannot clear caller cancellation");
            assert!(sibling.checkpoint().is_ok());
        }
    }

    #[test]
    fn shutdown_drain_refuses_unadmitted_peer_cancelled_and_failed_owners() {
        for refusal in 0..4 {
            let cx = Cx::for_testing();
            let shutdown = HttpListenerShutdown::new(&cx);
            let (subscription, terminal, request) = subscription_drain(refusal != 0);
            match refusal {
                0 => assert!(terminal.mark_cancellation_enqueued()),
                1 => { request.cancel(); }
                2 => {
                    assert!(terminal.mark_cancellation_enqueued());
                    terminal.mark_failed();
                }
                3 => {
                    terminal.mark_control_not_required();
                    terminal.mark_failed();
                    assert!(terminal.is_committed(), "control alone cannot prove successful receipt");
                }
                _ => unreachable!(),
            }
            cx.set_cancel_requested(true);
            let polls = AtomicUsize::new(0);
            let mut driving = Box::pin(drive_connection(
                &cx,
                &shutdown,
                &subscription,
                Duration::from_secs(1),
                poll_fn(|_| {
                    polls.fetch_add(1, Ordering::SeqCst);
                    Poll::Ready(())
                }),
            ));
            let mut task = Context::from_waker(Waker::noop());
            assert_eq!(
                driving.as_mut().poll(&mut task),
                Poll::Ready(Err(SecuredHttpEndpointError::Cancelled)),
                "refusal={refusal}"
            );
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert!(request.is_cancel_requested());
        }

        // An ordinary stream never installs this subscription-only slot.
        let cx = Cx::for_testing();
        let shutdown = HttpListenerShutdown::new(&cx);
        let subscription = SubscriptionDrain::default();
        cx.set_cancel_requested(true);
        let mut driving = Box::pin(drive_connection(
            &cx, &shutdown, &subscription, Duration::from_secs(1), async { 1 },
        ));
        let mut task = Context::from_waker(Waker::noop());
        assert_eq!(driving.as_mut().poll(&mut task), Poll::Ready(Err(SecuredHttpEndpointError::Cancelled)));
    }

    #[test]
    fn terminal_drain_keeps_one_bound_and_the_original_caller_deadline() {
        for caller_expires_first in [false, true] {
            let clock = Arc::new(asupersync::time::VirtualClock::new());
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .blocking_threads(0, 0)
                .with_timer_driver(asupersync::time::TimerDriverHandle::with_virtual_clock(
                    Arc::clone(&clock),
                ))
                .build()
                .unwrap();
            let budget = if caller_expires_first {
                asupersync::Budget::INFINITE.with_deadline(asupersync::Time::from_nanos(500_000_000))
            } else {
                asupersync::Budget::INFINITE
            };
            let cx = runtime.request_cx_with_budget(budget);
            let shutdown = HttpListenerShutdown::new(&cx);
            let (subscription, terminal, _) = subscription_drain(true);
            assert!(terminal.mark_cancellation_enqueued());
            cx.set_cancel_requested(true);
            let polls = AtomicUsize::new(0);
            let mut driving = Box::pin(drive_connection(
                &cx,
                &shutdown,
                &subscription,
                Duration::from_secs(1),
                poll_fn(|_| {
                    polls.fetch_add(1, Ordering::SeqCst);
                    assert!(cx.checkpoint().is_ok());
                    Poll::<()>::Pending
                }),
            ));
            let mut task = Context::from_waker(Waker::noop());
            assert!(driving.as_mut().poll(&mut task).is_pending());
            clock.advance_to(asupersync::Time::from_nanos(400_000_000));
            assert!(driving.as_mut().poll(&mut task).is_pending());
            clock.advance_to(asupersync::Time::from_nanos(if caller_expires_first {
                500_000_000
            } else {
                1_000_000_000
            }));
            assert_eq!(driving.as_mut().poll(&mut task), Poll::Ready(Err(SecuredHttpEndpointError::TimedOut)));
            assert_eq!(polls.load(Ordering::SeqCst), 2, "no write may resume at its exact bound");
            assert_eq!(terminal.state.load(Ordering::Acquire), FINAL_TERMINAL_FAILED);
            drop(driving);
            assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
        }
    }

    async fn bound(cx: &Cx) -> BoundSecuredHttpServer {
        let policy = HttpSecurityPolicy::new(
            HttpEndpointConfig::new("/mcp", HttpAdmissionLimits::new(32, 8192, 4096).unwrap())
                .unwrap(),
            "https://service.example",
            vec![],
        )
        .unwrap();
        Server::new("connection-budget-test", "1")
            .protocol_policy(ProtocolPolicy::ModernOnly)
            .unwrap()
            .build()
            .bind_secured_http(cx, "127.0.0.1:0", policy)
            .await
            .unwrap()
    }

    fn assert_disconnected(peer: &mut std::net::TcpStream) {
        // This is an upper failure bound on observing an already-dropped
        // socket, not a sleep used to guess whether cancellation happened.
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut byte = [0_u8; 1];
        match peer.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            other => panic!("refused connection must close without response bytes: {other:?}"),
        }
    }

    #[test]
    fn caller_cancellation_closes_native_idle_and_partial_head_connections() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let bound = bound(&cx).await;
                for prefix in [b"".as_slice(), b"POST /mcp HTTP/1.1\r\nHost:".as_slice()] {
                    let mut peer =
                        std::net::TcpStream::connect(bound.local_addr().unwrap()).unwrap();
                    peer.write_all(prefix).unwrap();
                    let (stream, _) = bound.inner.listener.accept().await.unwrap();
                    let endpoint = Arc::clone(&bound.inner.endpoint);
                    let sessions = Arc::clone(&bound.inner.modern_sessions);
                    let policy = Arc::clone(&bound.policy);
                    let io = bound.io;
                    let (sender, mut receiver) = asupersync::channel::oneshot::channel::<Cx>();
                    let mut child = cx
                        .spawn(move |child_cx| async move {
                            let subscription_drain = SubscriptionDrain::default();
                            let connection = connection::serve(
                                &child_cx,
                                ConnectionIo::Plain(stream),
                                endpoint,
                                sessions,
                                HttpListenerShutdown::new(&child_cx),
                                policy,
                                io,
                                &subscription_drain,
                            );
                            let mut driving = Box::pin(drive(&child_cx, connection));
                            let mut sender = Some(sender);
                            poll_fn(|task| {
                                let result = driving.as_mut().poll(task);
                                if result.is_pending()
                                    && let Some(sender) = sender.take()
                                {
                                    // A positive handshake proves the native ingress
                                    // is parked before the caller cancels its child.
                                    let _ = sender.send_blocking(child_cx.clone());
                                }
                                result
                            })
                            .await
                        })
                        .unwrap();
                    let child_cx = receiver.recv(&cx).await.unwrap();
                    // Cancel with an attributed reason, as the runtime does.
                    // A reasonless `set_cancel_requested` makes asupersync 0.5
                    // discard the task's value at `join` ("join channel
                    // closed"), hiding the refusal this test observes.
                    child_cx.cancel_with(
                        asupersync::types::CancelKind::User,
                        Some("caller cancelled the connection"),
                    );
                    let result = asupersync::time::timeout(
                        cx.now(),
                        Duration::from_secs(1),
                        child.join(&cx),
                    )
                    .await
                    .expect("cancelled connection must settle")
                    .unwrap();
                    assert_eq!(result, Err(SecuredHttpEndpointError::Cancelled));
                    assert!(
                        cx.checkpoint().is_ok(),
                        "a connection must not cancel its listener"
                    );
                    assert_disconnected(&mut peer);
                    assert!(
                        bound
                            .inner
                            .modern_sessions
                            .sessions
                            .lock()
                            .unwrap()
                            .is_empty()
                    );
                }
            });
    }

    #[test]
    fn unserviceable_caller_deadline_drops_native_socket_before_ingress() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let runtime_cx = Cx::current().unwrap();
                let bound = bound(&runtime_cx).await;
                let mut peer = std::net::TcpStream::connect(bound.local_addr().unwrap()).unwrap();
                let (stream, _) = bound.inner.listener.accept().await.unwrap();
                let cx = Cx::for_testing_with_budget(
                    asupersync::Budget::INFINITE
                        .with_deadline(asupersync::Time::ZERO.saturating_add_nanos(u64::MAX)),
                );
                assert!(cx.timer_driver().is_none());
                // Box the connection future rather than holding it inline. It
                // embeds `ingress::receive`, so it is large, and the two other
                // `connection::serve` call sites already box it -- the
                // production path at listener.rs:287 does so through an
                // explicit `Pin<Box<dyn Future>>`. This was the only site
                // keeping it on the stack.
                let subscription_drain = SubscriptionDrain::default();
                let connection = Box::pin(connection::serve(
                    &cx,
                    ConnectionIo::Plain(stream),
                    Arc::clone(&bound.inner.endpoint),
                    Arc::clone(&bound.inner.modern_sessions),
                    HttpListenerShutdown::new(&cx),
                    Arc::clone(&bound.policy),
                    bound.io,
                    &subscription_drain,
                ));
                let result = drive(&cx, connection).await;
                assert_eq!(result, Err(SecuredHttpEndpointError::TimerUnavailable));
                assert_disconnected(&mut peer);
                assert!(
                    bound
                        .inner
                        .modern_sessions
                        .sessions
                        .lock()
                        .unwrap()
                        .is_empty()
                );
                assert!(runtime_cx.checkpoint().is_ok());
            });
    }

    #[test]
    fn driverless_caller_still_times_out_an_idle_request_head() {
        // bd-if2ni: asupersync parks a timeout without a wake only through
        // `poll_with_time`. An awaited timeout polls its Sleep, which falls
        // back to the process-global timer, so the request timeout must fire
        // for a caller Cx with no timer driver. The second pass differs only
        // in owning a driver.
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let runtime_cx = Cx::current().unwrap();
                let bound = bound(&runtime_cx).await;
                let io =
                    SecuredHttpIoLimits::new(Duration::from_millis(50), Duration::from_secs(1))
                        .unwrap();
                for with_driver in [false, true] {
                    let cx = if with_driver {
                        runtime_cx.clone()
                    } else {
                        Cx::for_testing()
                    };
                    assert_eq!(cx.timer_driver().is_some(), with_driver);
                    let mut peer =
                        std::net::TcpStream::connect(bound.local_addr().unwrap()).unwrap();
                    let (stream, _) = bound.inner.listener.accept().await.unwrap();
                    let subscription_drain = SubscriptionDrain::default();
                    let connection = Box::pin(connection::serve(
                        &cx,
                        ConnectionIo::Plain(stream),
                        Arc::clone(&bound.inner.endpoint),
                        Arc::clone(&bound.inner.modern_sessions),
                        HttpListenerShutdown::new(&cx),
                        Arc::clone(&bound.policy),
                        io,
                        &subscription_drain,
                    ));
                    // The outer bound runs on the driver-owning runtime Cx, so
                    // an inner timeout that never wakes fails here, not hangs.
                    let result = asupersync::time::timeout(
                        runtime_cx.now(),
                        Duration::from_secs(5),
                        drive(&cx, connection),
                    )
                    .await
                    .expect("an idle request head must time out");
                    assert_eq!(result, Ok(()));
                    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                    let mut response = Vec::new();
                    let _ = peer.read_to_end(&mut response);
                    assert!(
                        response.starts_with(b"HTTP/1.1 408"),
                        "with_driver={with_driver}: {:?}",
                        String::from_utf8_lossy(&response)
                    );
                }
            });
    }

    #[test]
    fn cancelled_pending_connection_drops_custody_without_restarting_or_cancelling_siblings() {
        let cx = Cx::for_testing();
        let sibling = Cx::for_testing();
        let dropped = Arc::new(AtomicUsize::new(0));
        let owner = Owner(Arc::clone(&dropped));
        let started = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&started);
        let operation = async move {
            let _owner = owner;
            observed.fetch_add(1, Ordering::SeqCst);
            pending::<()>().await;
        };
        let mut driving = Box::pin(drive(&cx, operation));
        let counter = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&counter));
        let mut task = Context::from_waker(&waker);
        for _ in 0..3 {
            assert!(driving.as_mut().poll(&mut task).is_pending());
        }
        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "a partially driven operation must never restart"
        );
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        let wakes_before = counter.0.load(Ordering::SeqCst);
        cx.set_cancel_requested(true);
        assert!(
            counter.0.load(Ordering::SeqCst) > wakes_before,
            "an idle connection must wake without another I/O event"
        );
        assert_eq!(
            driving.as_mut().poll(&mut task),
            Poll::Ready(Err(SecuredHttpEndpointError::Cancelled))
        );
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            1,
            "native custody must drop before returning refusal"
        );
        assert!(sibling.checkpoint().is_ok());
    }

    #[test]
    fn abandoning_connection_driver_drops_custody_without_cancelling_its_caller() {
        let cx = Cx::for_testing();
        let dropped = Arc::new(AtomicUsize::new(0));
        let owner = Owner(Arc::clone(&dropped));
        let mut driving = Box::pin(drive(&cx, async move {
            let _owner = owner;
            pending::<()>().await;
        }));
        let mut task = Context::from_waker(Waker::noop());
        assert!(driving.as_mut().poll(&mut task).is_pending());
        drop(driving);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn request_token_cancellation_does_not_suppress_a_committed_terminal_drain() {
        let cx = Cx::for_testing();
        let request = McpRequestCancellation::new();
        request.cancel();
        let mut driving = Box::pin(drive(&cx, async {
            assert!(request.is_cancel_requested());
            // The native response state machine, not request-token liveness,
            // determines whether a graceful terminal still needs delivery.
            1_u8
        }));
        let mut task = Context::from_waker(Waker::noop());
        assert_eq!(driving.as_mut().poll(&mut task), Poll::Ready(Ok(1)));
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn cancellation_during_connection_completion_withholds_and_drops_the_result() {
        let cx = Cx::for_testing();
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut driving = Box::pin(drive(
            &cx,
            poll_fn(|_| {
                cx.set_cancel_requested(true);
                Poll::Ready(Owner(Arc::clone(&dropped)))
            }),
        ));
        let mut task = Context::from_waker(Waker::noop());
        assert!(matches!(
            driving.as_mut().poll(&mut task),
            Poll::Ready(Err(SecuredHttpEndpointError::Cancelled))
        ));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
}
