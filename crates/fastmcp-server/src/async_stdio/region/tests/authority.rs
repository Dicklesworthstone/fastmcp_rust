//! Capability ceilings must survive admission, publication and request work.
//! Uses the real runtime and existing bounded region-custody harness.

use super::*;

const ALL: u8 = 0b1_1111;
const SPAWN: u8 = 1;
const TIME: u8 = 2;
const ENTROPY: u8 = 4;
const IO: u8 = 8;
const REMOTE: u8 = 16;

fn row(cx: &Cx) -> u8 {
    let capabilities = cx.capabilities();
    u8::from(capabilities.spawn)
        | (u8::from(capabilities.time) << 1)
        | (u8::from(capabilities.entropy) << 2)
        | (u8::from(capabilities.io) << 3)
        | (u8::from(capabilities.remote) << 4)
}

fn mask(bits: u8) -> CapMask {
    let mut mask = CapMask::all();
    for (bit, without) in [
        (SPAWN, CapSet::<false, true, true, true, true>::MASK),
        (TIME, CapSet::<true, false, true, true, true>::MASK),
        (ENTROPY, CapSet::<true, true, false, true, true>::MASK),
        (IO, CapSet::<true, true, true, false, true>::MASK),
        (REMOTE, CapSet::<true, true, true, true, false>::MASK),
    ] {
        if bits & bit == 0 {
            mask = mask.intersect(without);
        }
    }
    assert_eq!(mask.bits(), bits);
    mask
}

fn held_view(cx: &Cx, bits: u8) -> Cx {
    let _caller = Cx::set_current(Some(cx.clone()));
    let _restriction = Cx::push_restriction(mask(bits));
    Cx::current().unwrap()
}

#[test]
fn native_admission_snapshots_every_ambient_capability_bit() {
    assert!(Cx::current().is_none());
    assert_eq!(ambient_capability_ceiling(), CapMask::all());
    let cx = Cx::for_testing();
    for bits in 0..=ALL {
        let _caller = Cx::set_current(Some(cx.clone()));
        let _restriction = Cx::push_restriction(mask(bits));
        let depth = Cx::restriction_depth();
        assert_eq!(row(&Cx::current().unwrap()), bits);
        assert_eq!(ambient_capability_ceiling().bits(), bits);
        assert_eq!(Cx::restriction_depth(), depth);
    }
    assert!(Cx::current().is_none());
    assert_eq!(row(&cx), ALL);
}

#[test]
fn native_admission_retains_all_sixteen_spawn_allowed_rows_in_request_work() {
    run(|cx, diagnostics| async move {
        let parent = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .unwrap();
        for bits in (SPAWN..=ALL).step_by(2) {
            let opening = {
                let _caller = Cx::set_current(Some(parent.cx().clone()));
                let _restriction = Cx::push_restriction(mask(bits));
                let depth = Cx::restriction_depth();
                let opening = open(parent.cx(), Budget::INFINITE).unwrap();
                assert_eq!(row(&Cx::current().unwrap()), bits);
                assert_eq!(Cx::restriction_depth(), depth);
                opening
            };
            // The narrow ambient frame is gone BEFORE either the admission
            // producer or the request body is polled. A poll-local check that
            // forgets to transfer the ceiling therefore cannot pass this test.
            assert_eq!(row(&Cx::current().unwrap()), ALL);
            let region = opening.await.unwrap();
            assert_eq!(row(region.cx()), bits);
            assert_eq!(
                children(&diagnostics, parent.region_id()),
                vec![region.region_id()],
            );
            let mut work = region
                .cx()
                .spawn(|work_cx| async move {
                    (row(&work_cx), row(&Cx::current().unwrap()))
                })
                .unwrap();
            let observed = std::future::poll_fn(|task| work.poll_join(task))
                .await
                .unwrap();
            assert_eq!(observed, (bits, bits));
            region.close().await.unwrap();
            assert!(children(&diagnostics, parent.region_id()).is_empty());
            assert_eq!(row(parent.cx()), ALL);
            parent_is_live(&diagnostics, &parent);
        }
        parent.close().await.unwrap();
    });
}

#[test]
fn native_admission_intersects_explicit_and_ambient_authority_in_both_directions() {
    run(|cx, diagnostics| async move {
        let parent = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .unwrap();
        for (explicit_bits, ambient_bits) in [
            (ALL, ALL & !IO),
            (ALL & !IO, ALL),
            (ALL & !IO, ALL & !ENTROPY),
            (ALL & !TIME, ALL & !REMOTE),
            (SPAWN, ALL),
        ] {
            let explicit = held_view(parent.cx(), explicit_bits);
            let opening = {
                let _ambient = Cx::set_current(Some(parent.cx().clone()));
                let _restriction = Cx::push_restriction(mask(ambient_bits));
                let opening = open(&explicit, Budget::INFINITE).unwrap();
                assert_eq!(row(&Cx::current().unwrap()), ambient_bits);
                opening
            };
            let region = opening.await.unwrap();
            assert_eq!(row(region.cx()), explicit_bits & ambient_bits);
            assert_eq!(row(&explicit), explicit_bits);
            assert_eq!(row(parent.cx()), ALL);
            region.close().await.unwrap();
            assert!(children(&diagnostics, parent.region_id()).is_empty());
        }
        parent_is_live(&diagnostics, &parent);
        parent.close().await.unwrap();
    });
}

#[test]
fn native_admission_foreign_ambient_owner_cannot_replace_request_identity_or_budget() {
    run(|cx, diagnostics| async move {
        let parent = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .unwrap();
        let foreign_deadline = cx.now().saturating_add_nanos(5_000_000_000);
        let foreign = cx
            .open_child_region(
                ChildRegionSpec::inherit()
                    .with_budget(Budget::INFINITE.with_deadline(foreign_deadline)),
            )
            .await
            .unwrap();
        let request_deadline = cx.now().saturating_add_nanos(20_000_000_000);
        let opening = {
            let _ambient = Cx::set_current(Some(foreign.cx().clone()));
            let _restriction = Cx::push_restriction(mask(ALL & !IO));
            open(
                parent.cx(),
                Budget::INFINITE.with_deadline(request_deadline),
            )
            .unwrap()
        };
        let region = opening.await.unwrap();
        assert_eq!(row(region.cx()), ALL & !IO);
        assert_eq!(region.cx().budget().deadline, Some(request_deadline));
        assert_eq!(
            children(&diagnostics, parent.region_id()),
            vec![region.region_id()],
        );
        assert!(children(&diagnostics, foreign.region_id()).is_empty());
        region.close().await.unwrap();
        parent_is_live(&diagnostics, &parent);
        parent_is_live(&diagnostics, &foreign);
        assert_eq!(row(parent.cx()), ALL);
        assert_eq!(row(foreign.cx()), ALL);
        foreign.close().await.unwrap();
        parent.close().await.unwrap();
    });
}

#[test]
fn native_admission_denied_spawn_never_mints_and_restores_the_ambient_frame() {
    run(|cx, diagnostics| async move {
        let parent = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .unwrap();
        for bits in (0..=ALL).step_by(2) {
            {
                let _ambient = Cx::set_current(Some(parent.cx().clone()));
                let _restriction = Cx::push_restriction(mask(bits));
                let depth = Cx::restriction_depth();
                assert!(open(parent.cx(), Budget::INFINITE).is_err());
                assert_eq!(row(&Cx::current().unwrap()), bits);
                assert_eq!(Cx::restriction_depth(), depth);
            }
            let explicit = held_view(parent.cx(), bits);
            let depth = Cx::restriction_depth();
            assert!(open(&explicit, Budget::INFINITE).is_err());
            assert_eq!(row(&Cx::current().unwrap()), ALL);
            assert_eq!(Cx::restriction_depth(), depth);
            assert!(children(&diagnostics, parent.region_id()).is_empty());
        }
        // A refused call must neither poison the caller nor globally narrow
        // later requests that do have authority.
        let control = open(parent.cx(), Budget::INFINITE).unwrap().await.unwrap();
        assert_eq!(row(control.cx()), ALL);
        control.close().await.unwrap();
        parent_is_live(&diagnostics, &parent);
        parent.close().await.unwrap();
    });
}

#[test]
fn native_admission_abandoned_restricted_publication_keeps_structured_cleanup() {
    run(|cx, diagnostics| async move {
        let parent = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .unwrap();
        let sibling = parent
            .cx()
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .unwrap();
        let opening = {
            let _ambient = Cx::set_current(Some(parent.cx().clone()));
            let _restriction = Cx::push_restriction(mask(SPAWN));
            open(parent.cx(), Budget::INFINITE).unwrap()
        };
        until(&cx, || opening.admission.is_finished()).await;
        assert_eq!(children(&diagnostics, parent.region_id()).len(), 2);
        drop(opening);
        until(&cx, || {
            children(&diagnostics, parent.region_id()) == vec![sibling.region_id()]
        })
        .await;
        parent_is_live(&diagnostics, &parent);
        parent_is_live(&diagnostics, &sibling);
        assert_eq!(row(sibling.cx()), ALL);
        sibling.close().await.unwrap();
        parent.close().await.unwrap();
    });
}
