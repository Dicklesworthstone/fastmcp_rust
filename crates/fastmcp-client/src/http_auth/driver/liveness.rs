//! Deferred launch delivery and caller authority through the public driver.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Wake};

use asupersync::Budget;
use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{TimerDriverHandle, VirtualClock};

use super::*;

const ALL: u8 = 31;
const TIME: u8 = 2;

fn runtime(test: impl FnOnce(&Cx, &TimerDriverHandle, &VirtualClock)) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .with_timer_driver(timer.clone())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    test(&cx, &timer, &clock);
    assert_eq!(timer.pending_count(), 0);
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn url() -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse("https://issuer.example/authorize?state=private").unwrap()
}

#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct Dropped(Arc<AtomicUsize>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn deferred_launch_wakes_the_latest_task_before_any_network_or_timer_activity() {
    runtime(|cx, timer, _| {
        let retained = Mutex::new(None);
        let drove = AtomicBool::new(false);
        let driver_calls = AtomicUsize::new(0);
        let polls = AtomicUsize::new(0);
        let old = Arc::new(Wakes::default());
        let latest = Arc::new(Wakes::default());
        let old_waker = Waker::from(Arc::clone(&old));
        let latest_waker = Waker::from(Arc::clone(&latest));
        let mut execution = Box::pin(with_authorization_driver(
            cx,
            Duration::from_secs(10),
            |launcher| {
                *retained.lock().unwrap() = Some(launcher);
                poll_fn(|_| {
                    polls.fetch_add(1, Ordering::SeqCst);
                    if drove.load(Ordering::SeqCst) {
                        Poll::Ready(Ok::<_, OAuthError>(42))
                    } else {
                        Poll::Pending
                    }
                })
            },
            |received| {
                driver_calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(received, url());
                async {
                    drove.store(true, Ordering::SeqCst);
                    Ok(())
                }
            },
        ));
        assert!(execution.as_mut().poll(&mut Context::from_waker(&old_waker)).is_pending());
        assert!(execution.as_mut().poll(&mut Context::from_waker(&latest_waker)).is_pending());
        assert_eq!(old.0.load(Ordering::SeqCst), 0);
        assert_eq!(latest.0.load(Ordering::SeqCst), 0);
        assert_eq!(driver_calls.load(Ordering::SeqCst), 0);
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        let launcher = retained.lock().unwrap().take().unwrap();
        // A separate thread publishes with no access to the driver's future or
        // any other source of executor wakeups. This is a real scheduling edge.
        std::thread::spawn(move || launcher.submit(url()))
            .join()
            .unwrap()
            .unwrap();
        assert_eq!(old.0.load(Ordering::SeqCst), 0);
        assert_eq!(latest.0.load(Ordering::SeqCst), 1);
        assert_eq!(driver_calls.load(Ordering::SeqCst), 0);
        assert_eq!(timer.process_timers(), 0);
        // Only poll after observing an actual wake, not a lucky manual repoll.
        latest.0.store(0, Ordering::SeqCst);
        assert!(execution.as_mut().poll(&mut Context::from_waker(&latest_waker)).is_pending());
        assert_eq!(driver_calls.load(Ordering::SeqCst), 1);
        assert!(latest.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            execution.as_mut().poll(&mut Context::from_waker(&latest_waker)),
            Poll::Ready(Ok(42))
        ));
        drop(execution);
        assert_eq!(driver_calls.load(Ordering::SeqCst), 1);
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(Arc::strong_count(&old), 2);
        assert_eq!(Arc::strong_count(&latest), 2);
        assert!(!cx.is_cancel_requested());
    });
}

#[test]
fn publication_before_registration_is_observed_without_losing_the_url() {
    runtime(|cx, timer, _| {
        let drove = AtomicBool::new(false);
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut execution = Box::pin(with_authorization_driver(
            cx,
            Duration::from_secs(10),
            |launcher| {
                // Factory execution precedes the first poll registration.
                launcher.submit(url()).unwrap();
                poll_fn(|_| {
                    if drove.load(Ordering::SeqCst) {
                        Poll::Ready(Ok::<_, OAuthError>(7))
                    } else {
                        Poll::Pending
                    }
                })
            },
            |received| {
                assert_eq!(received, url());
                async {
                    drove.store(true, Ordering::SeqCst);
                    Ok(())
                }
            },
        ));
        assert!(execution.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            execution.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Ok(7))
        ));
        drop(execution);
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(Arc::strong_count(&wakes), 2);
    });
}

#[test]
fn abandonment_releases_launch_waker_and_a_late_publish_cannot_restart_work() {
    runtime(|cx, timer, _| {
        let retained = Mutex::new(None);
        let drops = Arc::new(AtomicUsize::new(0));
        let owned = Dropped(Arc::clone(&drops));
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let driver_calls = AtomicUsize::new(0);
        let mut execution = Box::pin(with_authorization_driver(
            cx,
            Duration::from_secs(10),
            |launcher| {
                *retained.lock().unwrap() = Some(launcher);
                async move {
                    let _owned = owned;
                    std::future::pending::<Result<(), OAuthError>>().await
                }
            },
            |_| {
                driver_calls.fetch_add(1, Ordering::SeqCst);
                ready(Ok(()))
            },
        ));
        assert!(execution.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        let launcher = retained.lock().unwrap().take().unwrap();
        let slot = Arc::clone(&launcher.slot);
        assert!(slot.lock().unwrap().waiter.is_some());
        drop(execution);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(Arc::strong_count(&wakes), 2);
        assert_eq!(launcher.submit(url()), Err(OAuthError::BrowserLaunchFailed));
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        let slot = slot.lock().unwrap();
        assert!(slot.retired);
        assert!(slot.url.is_none());
        assert!(slot.waiter.is_none());
        assert_eq!(driver_calls.load(Ordering::SeqCst), 0);
        assert!(!cx.is_cancel_requested());
    });
}

// The safe Wake adapter is enough to test reentrancy, without RawWaker/unsafe.
struct ReentrantWake {
    slot: Arc<Mutex<LaunchSlot>>,
    wakes: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        assert!(self.slot.try_lock().is_ok(), "wake ran under launch-slot lock");
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for ReentrantWake {
    fn drop(&mut self) {
        assert!(self.slot.try_lock().is_ok(), "waker drop ran under launch-slot lock");
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn wake_replacement_consumption_and_retirement_never_invoke_user_code_under_lock() {
    for disposition in 0..4 {
        let slot = Arc::new(Mutex::new(LaunchSlot::default()));
        let scope = LaunchScope(Arc::clone(&slot));
        let wakes = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(ReentrantWake {
            slot: Arc::clone(&slot),
            wakes: Arc::clone(&wakes),
            drops: Arc::clone(&drops),
        }));
        scope.register(&waker).unwrap();
        drop(waker); // The slot owns the only remaining reference.
        match disposition {
            0 => {
                AuthorizationLauncher { slot: Arc::clone(&slot) }.submit(url()).unwrap();
                assert_eq!(scope.take_url().unwrap(), Some(url()));
                assert_eq!(wakes.load(Ordering::SeqCst), 1);
            }
            1 => {
                scope.register(Waker::noop()).unwrap();
                assert_eq!(wakes.load(Ordering::SeqCst), 0);
            }
            2 => {
                // A URL could have been present before a registration; its
                // consumption must also dispose of the now-unneeded waiter.
                slot.lock().unwrap().url = Some(url());
                assert_eq!(scope.take_url().unwrap(), Some(url()));
            }
            _ => {}
        }
        drop(scope);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(slot.lock().unwrap().waiter.is_none());
        assert!(slot.lock().unwrap().url.is_none());
    }
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

fn row(cx: &Cx) -> u8 {
    let c = cx.capabilities();
    u8::from(c.spawn)
        | (u8::from(c.time) << 1)
        | (u8::from(c.entropy) << 2)
        | (u8::from(c.io) << 3)
        | (u8::from(c.remote) << 4)
}

#[test]
fn operation_and_browser_factories_and_polls_observe_the_effective_caller_ceiling() {
    runtime(|cx, timer, _| {
        for ambient_bits in 0..=ALL {
            for explicit_bits in [ALL, ALL & !16] {
                let caller = held(cx, explicit_bits);
                let ambient = held(&Cx::for_testing(), ambient_bits);
                let expected = ambient_bits & explicit_bits;
                let factories = AtomicUsize::new(0);
                let browser_polls = AtomicUsize::new(0);
                let done = AtomicBool::new(false);
                let assert_current = || {
                    let current = Cx::current().unwrap();
                    assert_eq!(row(&current), expected);
                    assert_eq!(current.task_id(), caller.task_id());
                    assert_eq!(current.budget(), caller.budget());
                    assert!(current.timer_driver().is_some());
                };
                let mut execution = Box::pin(with_authorization_driver(
                    &caller,
                    Duration::from_secs(10),
                    |launcher| {
                        assert_current();
                        factories.fetch_add(1, Ordering::SeqCst);
                        async {
                            assert_current();
                            launcher.launch(url()).await?;
                            poll_fn(|_| {
                                assert_current();
                                if done.load(Ordering::SeqCst) {
                                    Poll::Ready(Ok::<_, OAuthError>(42))
                                } else {
                                    Poll::Pending
                                }
                            })
                            .await
                        }
                    },
                    |_| {
                        assert_current();
                        factories.fetch_add(1, Ordering::SeqCst);
                        async {
                            assert_current();
                            browser_polls.fetch_add(1, Ordering::SeqCst);
                            done.store(true, Ordering::SeqCst);
                            Ok(())
                        }
                    },
                ));
                let mut result = None;
                for _ in 0..4 {
                    let _ambient = Cx::set_current(Some(ambient.clone()));
                    let depth = Cx::restriction_depth();
                    let polled = execution.as_mut().poll(&mut Context::from_waker(Waker::noop()));
                    assert_eq!(row(&Cx::current().unwrap()), ambient_bits);
                    assert_eq!(Cx::restriction_depth(), depth);
                    if let Poll::Ready(outcome) = polled {
                        result = Some(outcome);
                        break;
                    }
                }
                drop(execution);
                let result = result.expect("bounded ready fixtures must finish");
                if expected & TIME == 0 {
                    assert!(matches!(
                        result,
                        Err(AuthorizationDriverError::Driver(OAuthError::RuntimeTimerUnavailable))
                    ));
                    assert_eq!(factories.load(Ordering::SeqCst), 0);
                    assert_eq!(browser_polls.load(Ordering::SeqCst), 0);
                } else {
                    assert_eq!(result.unwrap(), 42);
                    assert_eq!(factories.load(Ordering::SeqCst), 2);
                    assert_eq!(browser_polls.load(Ordering::SeqCst), 1);
                }
                assert_eq!(timer.pending_count(), 0);
                assert!(!caller.is_cancel_requested());
            }
        }
    });
}

#[test]
fn a_pending_driver_uses_each_new_ceiling_and_denied_time_retires_both_futures() {
    runtime(|cx, timer, _| {
        let expected = AtomicUsize::new(usize::from(ALL & !8));
        let operation_polls = AtomicUsize::new(0);
        let driver_polls = AtomicUsize::new(0);
        let drops = Arc::new(AtomicUsize::new(0));
        let operation_owned = Dropped(Arc::clone(&drops));
        let driver_owned = Dropped(Arc::clone(&drops));
        let mut execution = Box::pin(with_authorization_driver(
            cx,
            Duration::from_secs(10),
            |launcher| async {
                let _owned = operation_owned;
                launcher.launch(url()).await?;
                poll_fn(|_| {
                    assert_eq!(usize::from(row(&Cx::current().unwrap())), expected.load(Ordering::SeqCst));
                    operation_polls.fetch_add(1, Ordering::SeqCst);
                    Poll::<Result<(), OAuthError>>::Pending
                })
                .await
            },
            |_| async {
                let _owned = driver_owned;
                poll_fn(|_| {
                    assert_eq!(usize::from(row(&Cx::current().unwrap())), expected.load(Ordering::SeqCst));
                    driver_polls.fetch_add(1, Ordering::SeqCst);
                    Poll::<Result<(), OAuthError>>::Pending
                })
                .await
            },
        ));
        for bits in [ALL & !8, ALL & !4] {
            expected.store(usize::from(bits), Ordering::SeqCst);
            let _ambient = Cx::set_current(Some(held(&Cx::for_testing(), bits)));
            assert!(execution.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            assert_eq!(row(&Cx::current().unwrap()), bits);
        }
        assert_eq!(operation_polls.load(Ordering::SeqCst), 2);
        assert_eq!(driver_polls.load(Ordering::SeqCst), 1);
        let _ambient = Cx::set_current(Some(held(&Cx::for_testing(), ALL & !TIME)));
        assert!(matches!(
            execution.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(AuthorizationDriverError::Driver(OAuthError::RuntimeTimerUnavailable)))
        ));
        drop(execution);
        assert_eq!(operation_polls.load(Ordering::SeqCst), 2);
        assert_eq!(driver_polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(timer.pending_count(), 0);
        assert!(!cx.is_cancel_requested());
    });
}

#[test]
fn deadline_and_cancellation_retire_a_deferred_launcher_without_starting_a_browser() {
    for cancelled in [false, true] {
        runtime(|cx, timer, clock| {
            let retained = Mutex::new(None);
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut execution = Box::pin(with_authorization_driver(
                cx,
                Duration::from_secs(1),
                |launcher| {
                    *retained.lock().unwrap() = Some(launcher);
                    std::future::pending::<Result<(), OAuthError>>()
                },
                |_| -> Ready<Result<(), OAuthError>> {
                    panic!("no URL has been published")
                },
            ));
            assert!(execution.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
            assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
            if cancelled {
                cx.set_cancel_requested(true);
            } else {
                clock.advance(1_000_000_000);
                assert!(timer.process_timers() > 0);
            }
            assert!(wakes.0.load(Ordering::SeqCst) > 0);
            let result = execution.as_mut().poll(&mut Context::from_waker(&waker));
            match (cancelled, result) {
                (true, Poll::Ready(Err(AuthorizationDriverError::Driver(OAuthError::Cancelled))))
                | (false, Poll::Ready(Err(AuthorizationDriverError::Driver(OAuthError::TimedOut)))) => {}
                _ => panic!("original lifetime failure must remain authoritative"),
            }
            drop(execution);
            assert_eq!(timer.pending_count(), 0);
            assert_eq!(Arc::strong_count(&wakes), 2);
            let before = wakes.0.load(Ordering::SeqCst);
            assert_eq!(
                retained.lock().unwrap().take().unwrap().submit(url()),
                Err(OAuthError::BrowserLaunchFailed)
            );
            assert_eq!(wakes.0.load(Ordering::SeqCst), before);
        });
    }
}
