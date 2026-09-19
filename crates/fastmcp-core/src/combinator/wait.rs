//! Caller-owned cancellation admission for the result-returning combinators.

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::{Context, Poll};

use asupersync::Cx;
use asupersync::channel::oneshot;

use super::{BoxFuture, poll_slot};
use crate::error::{McpError, McpResult};

fn checkpoint(cx: &Cx) -> McpResult<()> {
    cx.checkpoint().map_err(|_| McpError::request_cancelled())
}

/// Poll one active slot without admitting work after caller cancellation or
/// publishing a value produced by a child that cancelled its caller mid-poll.
/// Completed slots have no work left to admit and consume no checkpoints.
pub(super) fn poll_active<T>(
    cx: &Cx,
    slot: &mut Option<BoxFuture<'_, T>>,
    task: &mut Context<'_>,
) -> McpResult<Option<T>> {
    if slot.is_none() {
        return Ok(None);
    }
    checkpoint(cx)?;
    let result = poll_slot(slot, task);
    checkpoint(cx)?;
    Ok(result)
}

/// Await a caller-owned future with a native cancellation wakeup. A checkpoint
/// alone cannot wake a task whose children all remain pending. The unsent
/// oneshot's receive registers with the supplied Cx and retires that exact
/// registration on completion, cancellation, panic, or owner abandonment.
pub(super) async fn cancellable<T>(
    cx: &Cx,
    future: impl Future<Output = McpResult<T>>,
) -> McpResult<T> {
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = pin!(receiver.recv(cx));
    let mut future = pin!(future);

    poll_fn(|task| {
        checkpoint(cx)?;
        // Native timers and I/O must resolve the caller's drivers, not an
        // unrelated ambient context. The guard never crosses a suspension.
        let _caller = Cx::set_current(Some(cx.clone()));
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(McpError::request_cancelled()));
        }
        let result = future.as_mut().poll(task);
        checkpoint(cx)?;
        result
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};
    use std::time::Duration;

    use super::*;
    use crate::combinator::{first_ok, quorum, quorum_timeout, race, race_timeout};
    use crate::error::McpErrorCode;

    #[derive(Clone, Copy, Debug)]
    enum Kind {
        Race,
        TimedRace,
        Quorum,
        TimedQuorum,
        FirstOk,
    }

    const KINDS: [Kind; 5] = [
        Kind::Race,
        Kind::TimedRace,
        Kind::Quorum,
        Kind::TimedQuorum,
        Kind::FirstOk,
    ];

    fn run<'a>(
        kind: Kind,
        cx: &'a Cx,
        futures: Vec<BoxFuture<'a, McpResult<i32>>>,
    ) -> BoxFuture<'a, McpResult<i32>> {
        Box::pin(async move {
            match kind {
                Kind::Race => race(cx, futures).await?,
                Kind::TimedRace => race_timeout(cx, Duration::MAX, futures).await?,
                Kind::Quorum => Ok(quorum(cx, 1, futures).await?.successes[0]),
                Kind::TimedQuorum => {
                    Ok(quorum_timeout(cx, 1, Duration::MAX, futures).await?.successes[0])
                }
                Kind::FirstOk => first_ok(cx, futures).await,
            }
        })
    }

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct Probe {
        ready: bool,
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl Future for Probe {
        type Output = McpResult<i32>;

        fn poll(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            if self.ready {
                Poll::Ready(Ok(42))
            } else {
                Poll::Pending
            }
        }
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn probes(
        count: usize,
        ready: bool,
        polls: &Arc<AtomicUsize>,
        drops: &Arc<AtomicUsize>,
    ) -> Vec<BoxFuture<'static, McpResult<i32>>> {
        (0..count)
            .map(|_| {
                Box::pin(Probe {
                    ready,
                    polls: Arc::clone(polls),
                    drops: Arc::clone(drops),
                }) as BoxFuture<'static, McpResult<i32>>
            })
            .collect()
    }

    #[test]
    fn cancellation_wakes_pending_waits_without_a_child_wakeup() {
        for kind in KINDS {
            for count in [1, 2] {
                let cx = Cx::for_testing();
                let polls = Arc::new(AtomicUsize::new(0));
                let drops = Arc::new(AtomicUsize::new(0));
                let counter = Arc::new(WakeCounter::default());
                let waker = Waker::from(Arc::clone(&counter));
                let mut task = Context::from_waker(&waker);
                let mut future = run(kind, &cx, probes(count, false, &polls, &drops));

                assert!(future.as_mut().poll(&mut task).is_pending(), "{kind:?}");
                assert_eq!(polls.load(Ordering::Relaxed), count);
                assert_eq!(counter.0.load(Ordering::Relaxed), 0);
                cx.set_cancel_requested(true);
                // Assert the wake *before* any manual repoll. A checkpoint-only
                // implementation can pass a repoll test while hanging in use.
                assert!(counter.0.load(Ordering::Relaxed) > 0, "{kind:?}");
                let Poll::Ready(result) = future.as_mut().poll(&mut task) else {
                    panic!("cancelled {kind:?} stayed pending");
                };
                assert_eq!(result.unwrap_err().code, McpErrorCode::RequestCancelled);
                assert_eq!(polls.load(Ordering::Relaxed), count);
                assert_eq!(drops.load(Ordering::Relaxed), count);
            }
        }
    }

    #[test]
    fn cancelled_or_exhausted_callers_never_poll_ready_children() {
        for kind in KINDS {
            for exhausted in [false, true] {
                let cx = if exhausted {
                    Cx::for_testing_with_budget(asupersync::Budget::ZERO)
                } else {
                    let cx = Cx::for_testing();
                    cx.set_cancel_requested(true);
                    cx
                };
                let polls = Arc::new(AtomicUsize::new(0));
                let drops = Arc::new(AtomicUsize::new(0));
                let mut future = run(kind, &cx, probes(2, true, &polls, &drops));
                let mut task = Context::from_waker(Waker::noop());
                let Poll::Ready(result) = future.as_mut().poll(&mut task) else {
                    panic!("inactive {kind:?} stayed pending");
                };
                assert_eq!(result.unwrap_err().code, McpErrorCode::RequestCancelled);
                assert_eq!(polls.load(Ordering::Relaxed), 0);
                assert_eq!(drops.load(Ordering::Relaxed), 2);
            }
        }
    }

    #[test]
    fn mid_poll_cancellation_prevents_publication_and_later_side_effects() {
        for kind in KINDS {
            for ready in [false, true] {
                let cx = Cx::for_testing();
                let cancelling_cx = cx.clone();
                let futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![
                    Box::pin(poll_fn(move |_| {
                        cancelling_cx.set_cancel_requested(true);
                        if ready {
                            Poll::Ready(Ok(7))
                        } else {
                            Poll::Pending
                        }
                    })),
                    Box::pin(async { panic!("cancelled caller admitted a later operation") }),
                ];
                let mut future = run(kind, &cx, futures);
                let mut task = Context::from_waker(Waker::noop());
                let Poll::Ready(result) = future.as_mut().poll(&mut task) else {
                    panic!("mid-poll cancellation of {kind:?} was lost");
                };
                assert_eq!(result.unwrap_err().code, McpErrorCode::RequestCancelled);
            }
        }
    }

    #[test]
    fn dropping_a_wait_retires_its_cancellation_registration() {
        for kind in KINDS {
            let cx = Cx::for_testing();
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let counter = Arc::new(WakeCounter::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = Context::from_waker(&waker);
            let mut future = run(kind, &cx, probes(1, false, &polls, &drops));
            assert!(future.as_mut().poll(&mut task).is_pending());

            drop(future);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(Arc::strong_count(&counter), 2, "{kind:?} retained a waker");
            cx.set_cancel_requested(true);
            assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn cancellation_wakes_the_latest_executor_waker() {
        for kind in KINDS {
            let cx = Cx::for_testing();
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let old = Arc::new(WakeCounter::default());
            let latest = Arc::new(WakeCounter::default());
            let old_waker = Waker::from(Arc::clone(&old));
            let latest_waker = Waker::from(Arc::clone(&latest));
            let mut future = run(kind, &cx, probes(1, false, &polls, &drops));
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(&old_waker))
                    .is_pending()
            );
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(&latest_waker))
                    .is_pending()
            );
            cx.set_cancel_requested(true);
            assert_eq!(old.0.load(Ordering::Relaxed), 0);
            assert!(latest.0.load(Ordering::Relaxed) > 0, "{kind:?}");
        }
    }

    #[test]
    fn each_poll_uses_the_supplied_context_and_restores_the_ambient_context() {
        for kind in KINDS {
            let ambient = Cx::for_testing();
            let _ambient = Cx::set_current(Some(ambient.clone()));
            let cx = Cx::for_testing();
            let futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![Box::pin(async {
                Cx::current()
                    .expect("caller context not installed")
                    .set_cancel_requested(true);
                Ok(42)
            })];
            let mut future = run(kind, &cx, futures);
            let mut task = Context::from_waker(Waker::noop());
            let Poll::Ready(result) = future.as_mut().poll(&mut task) else {
                panic!("ambient cancellation of {kind:?} stayed pending");
            };
            assert_eq!(result.unwrap_err().code, McpErrorCode::RequestCancelled);
            assert!(cx.is_cancel_requested());
            assert!(!ambient.is_cancel_requested());
            Cx::current()
                .expect("ambient context not restored")
                .set_cancel_requested(true);
            assert!(ambient.is_cancel_requested());
        }
    }

    #[test]
    fn live_callers_still_receive_ready_results_and_release_registrations() {
        for kind in KINDS {
            let cx = Cx::for_testing();
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let counter = Arc::new(WakeCounter::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = Context::from_waker(&waker);
            let mut future = run(kind, &cx, probes(2, true, &polls, &drops));
            let Poll::Ready(result) = future.as_mut().poll(&mut task) else {
                panic!("ready {kind:?} stayed pending");
            };
            assert_eq!(result.unwrap(), 42);
            assert_eq!(polls.load(Ordering::Relaxed), 1);
            assert_eq!(drops.load(Ordering::Relaxed), 2);
            assert_eq!(Arc::strong_count(&counter), 2);
            cx.set_cancel_requested(true);
            assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        }
    }
}
