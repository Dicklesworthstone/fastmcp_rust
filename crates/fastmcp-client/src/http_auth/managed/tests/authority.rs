//! Exercise managed acquisition and response custody under restricted callers.

use super::*;
use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::time::{TimerDriverHandle, VirtualClock};
use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::task::{Context, Wake, Waker};

const ALL: u8 = 31;
const TIME: u8 = 2;

fn mask(bits: u8) -> CapMask {
    let mut mask = CapMask::all();
    for (bit, without) in [
        (1, CapSet::<false, true, true, true, true>::MASK),
        (2, CapSet::<true, false, true, true, true>::MASK),
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

fn row(cx: &Cx) -> u8 {
    let caps = cx.capabilities();
    u8::from(caps.spawn)
        | (u8::from(caps.time) << 1)
        | (u8::from(caps.entropy) << 2)
        | (u8::from(caps.io) << 3)
        | (u8::from(caps.remote) << 4)
}

fn held(cx: &Cx, bits: u8) -> Cx {
    let _caller = Cx::set_current(Some(cx.clone()));
    let _restriction = Cx::push_restriction(mask(bits));
    Cx::current().unwrap()
}

fn runtime() -> (Runtime, Cx, TimerDriverHandle, Arc<VirtualClock>) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .with_timer_driver(timer.clone())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    (runtime, cx, timer, clock)
}

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct Owned(Arc<AtomicUsize>);
impl Drop for Owned {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn managed_wait_preserves_all_explicit_and_ambient_effect_intersections() {
    let (runtime, cx, timer, _) = runtime();
    let session = response_custody_session();
    let cancellation = McpRequestCancellation::new();
    let deadline = cx.now().saturating_add_nanos(10_000_000_000);
    for explicit in 0..=ALL {
        let caller = held(&cx, explicit);
        for ambient in 0..=ALL {
            let surrounding = held(&Cx::for_testing(), ambient);
            let expected = explicit & ambient;
            let polls = AtomicUsize::new(0);
            let mut wait = Box::pin(session.await_active(
                &caller,
                &cancellation,
                deadline,
                None,
                async {
                    polls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(row(&Cx::current().unwrap()), expected);
                    Ok(42)
                },
            ));
            let _surrounding = Cx::set_current(Some(surrounding));
            let depth = Cx::restriction_depth();
            let admission = deadline_after(&caller, Duration::from_secs(10));
            let outcome = wait.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            if expected & TIME != 0 {
                assert_eq!(admission.unwrap(), deadline);
                assert!(matches!(outcome, Poll::Ready(Ok(42))));
                assert_eq!(polls.load(Ordering::SeqCst), 1);
            } else {
                assert!(matches!(admission, Err(OAuthSessionError::RuntimeTimerUnavailable)));
                assert!(matches!(outcome, Poll::Ready(Err(OAuthSessionError::RuntimeTimerUnavailable))));
                assert_eq!(polls.load(Ordering::SeqCst), 0);
            }
            assert_eq!(row(&Cx::current().unwrap()), ambient);
            assert_eq!(Cx::restriction_depth(), depth);
            drop(wait);
            assert_eq!(timer.pending_count(), 0);
        }
    }
    assert!(!cancellation.is_cancel_requested());
    assert!(!cx.is_cancel_requested());
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn denied_acquisition_does_not_take_a_permit_or_touch_locked_grant_state() {
    let (runtime, cx, timer, _) = runtime();
    let session = response_custody_session();
    let guard = session.inner.state.try_lock_owned().unwrap();
    for bits in [ALL & !TIME, 0, TIME] {
        let _ambient = Cx::set_current(Some(held(&Cx::for_testing(), bits)));
        let mut acquisition = Box::pin(session.credential(&cx));
        let result = acquisition.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        if bits & TIME == 0 {
            assert!(matches!(result, Poll::Ready(Err(OAuthSessionError::RuntimeTimerUnavailable))));
            assert_eq!(session.inner.pending.load(Ordering::Acquire), 0);
        } else {
            // No I/O capability is needed just to await the already-owned
            // grant lock. Do not introduce an unrelated blanket I/O refusal.
            assert!(result.is_pending());
            assert_eq!(session.inner.pending.load(Ordering::Acquire), 1);
        }
        drop(acquisition);
        assert_eq!(session.inner.pending.load(Ordering::Acquire), 0);
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(row(&Cx::current().unwrap()), bits);
        assert!(guard.is_none());
    }
    drop(guard);
    assert!(session.inner.state.try_lock_owned().unwrap().is_none());
    assert!(!session.inner.closed.is_cancel_requested());
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn narrower_pending_scope_retires_owned_work_and_all_wait_registrations() {
    let (runtime, cx, timer, _) = runtime();
    let session = response_custody_session();
    let cancellation = McpRequestCancellation::new();
    let observed = RefCell::new(Vec::new());
    let drops = Arc::new(AtomicUsize::new(0));
    let owned = Owned(Arc::clone(&drops));
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut wait = Box::pin(session.await_active(
        &cx,
        &cancellation,
        cx.now().saturating_add_nanos(10_000_000_000),
        None,
        async {
            let _owned = owned;
            poll_fn(|_| {
                observed.borrow_mut().push(row(&Cx::current().unwrap()));
                Poll::<Result<(), OAuthSessionError>>::Pending
            })
            .await
        },
    ));
    for bits in [ALL, TIME] {
        let _ambient = Cx::set_current(Some(held(&Cx::for_testing(), bits)));
        assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }
    assert_eq!(timer.pending_count(), 1);
    {
        let _ambient = Cx::set_current(Some(held(&Cx::for_testing(), ALL & !TIME)));
        assert!(matches!(
            wait.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(OAuthSessionError::RuntimeTimerUnavailable))
        ));
        assert_eq!(row(&Cx::current().unwrap()), ALL & !TIME);
    }
    drop(wait);
    assert_eq!(*observed.borrow(), [ALL, TIME]);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(timer.pending_count(), 0);
    assert_eq!(Arc::strong_count(&wakes), 2);
    cancellation.cancel();
    session.close();
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    assert!(!cx.is_cancel_requested());
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn foreign_clock_and_cancellation_do_not_replace_the_managed_owner() {
    let (caller_runtime, cx, timer, clock) = runtime();
    let (foreign_runtime, foreign, foreign_timer, foreign_clock) = runtime();
    clock.advance(7_000_000_000);
    foreign_clock.advance(1_000_000_000);
    foreign.set_cancel_requested(true);
    let session = response_custody_session();
    let cancellation = McpRequestCancellation::new();
    {
        let _ambient = Cx::set_current(Some(held(&foreign, TIME)));
        let deadline = deadline_after(&cx, Duration::from_secs(10)).unwrap();
        assert_eq!(deadline.as_nanos(), 17_000_000_000);
        let mut wait = Box::pin(session.await_active(&cx, &cancellation, deadline, None, async {
            let active = Cx::current().unwrap();
            assert_eq!(row(&active), TIME);
            assert_eq!(active.now(), cx.now());
            assert_ne!(active.now(), foreign.now());
            assert_eq!(active.budget().deadline, cx.budget().deadline);
            assert!(active.checkpoint().is_ok());
            Ok(42)
        }));
        assert!(matches!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(42))
        ));
        assert!(Cx::current().unwrap().is_cancel_requested());
    }
    assert_eq!(timer.pending_count(), 0);
    assert_eq!(foreign_timer.pending_count(), 0);
    assert!(!cx.is_cancel_requested());
    drop(foreign);
    drop(cx);
    assert!(foreign_runtime.shutdown_timeout(Duration::from_secs(1)));
    assert!(caller_runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn unwind_restores_the_ambient_frame_and_disposes_managed_wait_state() {
    let (runtime, cx, timer, _) = runtime();
    let session = response_custody_session();
    let cancellation = McpRequestCancellation::new();
    {
        let _ambient = Cx::set_current(Some(held(&Cx::for_testing(), TIME)));
        let depth = Cx::restriction_depth();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut wait = Box::pin(session.await_active(
                &cx,
                &cancellation,
                cx.now().saturating_add_nanos(10_000_000_000),
                None,
                poll_fn(|_| -> Poll<Result<(), OAuthSessionError>> {
                    assert_eq!(row(&Cx::current().unwrap()), TIME);
                    panic!("test-only host panic");
                }),
            ));
            let _ = wait.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        }));
        assert!(result.is_err());
        assert_eq!(row(&Cx::current().unwrap()), TIME);
        assert_eq!(Cx::restriction_depth(), depth);
    }
    assert_eq!(timer.pending_count(), 0);
    assert!(!session.inner.closed.is_cancel_requested());
    assert!(!cancellation.is_cancel_requested());
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn public_json_and_sse_reads_release_custody_when_time_authority_is_denied() {
    for sse in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let listener = asupersync::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let session = response_custody_session();
            let cancellation = McpRequestCancellation::new();
            let application = async {
                let response = open_response(
                    &cx, &listener, &session, &cancellation, Duration::from_secs(30),
                ).await;
                if sse {
                    let mut stream = response.into_sse_stream(SseLimits::new(4096, 65536, 8).unwrap()).unwrap();
                    assert_eq!(stream.next_event(&cx).await.unwrap(), Some("first".to_owned()));
                    let mut read = Box::pin(stream.next_event(&cx));
                    let result = poll_fn(|task| {
                        let _restriction = Cx::push_restriction(mask(ALL & !TIME));
                        read.as_mut().poll(task)
                    }).await;
                    assert!(matches!(result, Err(OAuthSessionError::RuntimeTimerUnavailable)));
                    drop(read);
                    assert!(matches!(stream.next_event(&cx).await,
                        Err(OAuthSessionError::Http(ModernHttpExecutorError::SseStreamClosed))));
                } else {
                    let mut read = Box::pin(response.read_to_end(&cx, 4096));
                    let result = poll_fn(|task| {
                        let _restriction = Cx::push_restriction(mask(ALL & !TIME));
                        read.as_mut().poll(task)
                    }).await;
                    assert!(matches!(result, Err(OAuthSessionError::RuntimeTimerUnavailable)));
                }
                assert!(!session.inner.closed.is_cancel_requested());
                assert!(!cancellation.is_cancel_requested());
                assert!(cx.checkpoint().is_ok());
            };
            // Existing peer requires the owned read to close its actual socket.
            // This is response custody, not an authenticated-login test.
            pair(application, response_peer(&listener, sse, true)).await;
        });
    }
}
