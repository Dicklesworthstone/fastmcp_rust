//! Poll-local caller identity with a non-widening ambient effect ceiling.
//!
//! Installing a supplied Cx selects its drivers, budget and cancellation, but
//! replaces the ambient frame's restrictions. Capture those restrictions
//! BEFORE replacement and intersect them afterwards. No guard may escape this
//! synchronous scope or remain installed across an await.

use asupersync::Cx;
use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};

pub(super) fn with_caller<T>(cx: &Cx, operation: impl FnOnce() -> T) -> T {
    let ceiling = ambient_ceiling();
    let _caller = Cx::set_current(Some(cx.clone()));
    let _restriction = Cx::push_restriction(ceiling);
    operation()
}

// Use the pinned runtime's public sealed masks, not raw bits or a fabricated
// Cx. An unrelated ambient caller contributes ONLY effects, never identity,
// budget, cancellation or a replacement I/O/timer driver.
fn ambient_ceiling() -> CapMask {
    let Some(active) = Cx::current() else {
        return CapMask::all();
    };
    let capabilities = active.capabilities();
    let mut ceiling = CapMask::all();
    for (allowed, without) in [
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
            ceiling = ceiling.intersect(without);
        }
    }
    ceiling
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::time::Duration;

    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::time::{TimerDriverHandle, VirtualClock};

    use super::*;

    const ALL: u8 = 31;

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

    fn held(cx: &Cx, bits: u8) -> Cx {
        let _caller = Cx::set_current(Some(cx.clone()));
        let _restriction = Cx::push_restriction(mask(bits));
        Cx::current().unwrap()
    }

    #[test]
    fn every_explicit_and_ambient_capability_combination_is_intersected() {
        let full = Cx::for_testing();
        for explicit in 0..=ALL {
            let caller = held(&full, explicit);
            for ambient in 0..=ALL {
                let active = held(&full, ambient);
                let _ambient = Cx::set_current(Some(active));
                let depth = Cx::restriction_depth();
                let captured = with_caller(&caller, || {
                    assert_eq!(row(&Cx::current().unwrap()), explicit & ambient);
                    Cx::current().unwrap()
                });
                assert_eq!(row(&captured), explicit & ambient);
                assert_eq!(row(&Cx::current().unwrap()), ambient);
                assert_eq!(Cx::restriction_depth(), depth);
            }
            assert_eq!(row(&caller), explicit);
        }
        assert_eq!(row(&full), ALL);
    }

    #[test]
    fn nested_and_unwinding_scopes_restore_the_callers_exact_frame() {
        let cx = Cx::for_testing();
        let active = held(&cx, ALL & !8);
        let _ambient = Cx::set_current(Some(active));
        let depth = Cx::restriction_depth();
        let result = catch_unwind(AssertUnwindSafe(|| {
            with_caller(&cx, || {
                let _extra = Cx::push_restriction(mask(ALL & !16));
                with_caller(&cx, || {
                    assert_eq!(row(&Cx::current().unwrap()), ALL & !8 & !16);
                    panic!("scope unwind probe");
                });
            });
        }));
        assert!(result.is_err());
        assert_eq!(row(&Cx::current().unwrap()), ALL & !8);
        assert_eq!(Cx::restriction_depth(), depth);
        assert_eq!(with_caller(&cx, || 42), 42);
        assert!(!cx.is_cancel_requested());
    }

    #[test]
    fn absent_ambient_context_uses_the_explicit_ceiling_and_is_restored() {
        let cx = Cx::for_testing();
        let caller = held(&cx, ALL & !4);
        let _empty = Cx::set_current(None);
        let depth = Cx::restriction_depth();
        with_caller(&caller, || {
            assert_eq!(row(&Cx::current().unwrap()), ALL & !4);
        });
        assert!(Cx::current().is_none());
        assert_eq!(Cx::restriction_depth(), depth);
    }

    #[test]
    fn ambient_identity_deadline_cancellation_and_clock_never_replace_the_caller() {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let caller = runtime.request_cx_with_budget(Budget::INFINITE);
        let foreign = Cx::for_testing_with_budget(Budget::ZERO);
        foreign.set_cancel_requested(true);
        let ambient_guard = Cx::set_current(Some(foreign.clone()));
        clock.advance(123);
        with_caller(&caller, || {
            let current = Cx::current().unwrap();
            assert_eq!(current.region_id(), caller.region_id());
            assert_eq!(current.task_id(), caller.task_id());
            assert_eq!(current.budget(), caller.budget());
            assert_eq!(current.now(), timer.now());
            assert!(current.timer_driver().is_some());
            assert!(!current.is_cancel_requested());
        });
        assert!(Cx::current().unwrap().is_cancel_requested());
        assert!(Cx::current().unwrap().timer_driver().is_none());
        assert_eq!(timer.pending_count(), 0);
        drop(ambient_guard);
        drop(caller);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}
