//! LIMIT-01 implementation B frozen proofs, as an EXTERNAL consumer.
//!
//! bd-600a3. These four IDs previously existed only inside
//! `crates/fastmcp-core/src/lib.rs` under `#[cfg(test)]`, where they could
//! observe the crate from the inside. PL-3 makes that inadmissible for a
//! capability Bead: `cfg(test)` behaviour cannot prove shipped behaviour, and
//! an A/B frozen pair exists precisely to bind the PUBLIC surface.
//!
//! This target links `fastmcp-core` the way any dependent does, through
//! `use fastmcp_core::...` only. The in-crate copies are left untouched; a
//! duplicate ID inside a `mod tests` does not collide with a root-level one,
//! so both coexist and `--exact` still resolves each to one definition.
//!
//! NOTHING WAS RE-EXPORTED TO MAKE THIS COMPILE. Every symbol these tests
//! touch was already public at the crate root (`lib.rs:2229`), so the
//! `cfg(test)` placement was never forced by the API — which is the finding,
//! not just the fix.

mod limit_01_rows;

fn limit_01_b_limits() -> fastmcp_core::ProtocolLimits {
    fastmcp_core::ProtocolLimits::try_new(
        fastmcp_core::DEFAULT_JSON_RPC_MAX_BODY_BYTES,
        fastmcp_core::DEFAULT_METADATA_MAX_ENTRIES,
        fastmcp_core::DEFAULT_METADATA_MAX_BYTES,
        fastmcp_core::DEFAULT_URI_MAX_BYTES,
        fastmcp_core::DEFAULT_CANCELLATION_REASON_MAX_BYTES,
        fastmcp_core::DEFAULT_CURSOR_MAX_BYTES,
    )
    .expect("documented defaults must admit")
}
fn limit_01_b_partition(source: &str) -> fastmcp_core::AdmissionPartition {
    fastmcp_core::AdmissionPartition::pre_auth(
        fastmcp_core::PreAuthSourceBucketKey::from_listener_and_source("mcp.example.test", source)
            .expect("transport-observed source is admitted"),
    )
}

/// LIMIT-01 B positive: reserve N-1/N, commit/release lifecycle, two-partition fairness.
#[test]

fn limit_01_b_positive() {
    const N: usize = 4;
    let snapshot = limit_01_b_limits();
    let controller =
        fastmcp_core::AdmissionController::with_capacity(snapshot.snapshot(), N).expect("capacity N");
    let partition = limit_01_b_partition("tcp:203.0.113.8");

    let mut held_n_minus_one = controller
        .reserve(partition.clone(), N - 1)
        .expect("N-1 admits");
    assert_eq!(controller.global_in_use(), N - 1);
    assert_eq!(controller.partition_in_use(&partition), N - 1);
    held_n_minus_one.release().expect("release N-1");
    assert_eq!(controller.global_in_use(), 0);
    assert_eq!(controller.release_count(), 1);

    let mut held_n = controller.reserve(partition.clone(), N).expect("N admits");
    assert_eq!(controller.global_in_use(), N);
    assert_eq!(
        controller
            .reserve(partition.clone(), 1)
            .expect_err("N+1 partition"),
        fastmcp_core::AdmissionError::PartitionCapacityExceeded {
            requested: 1,
            in_use: N,
            limit: N,
        }
    );
    assert_eq!(controller.global_in_use(), N);
    held_n.commit().expect("commit transfers occupancy");
    assert_eq!(controller.global_in_use(), N);
    assert_eq!(controller.committed_work(), N);
    held_n.release().expect("release committed work");
    assert_eq!(controller.global_in_use(), 0);
    assert_eq!(controller.committed_work(), 0);
    assert_eq!(controller.release_count(), 2);

    {
        let _dropped = controller
            .reserve(partition.clone(), 1)
            .expect("drop path admits");
        assert_eq!(controller.global_in_use(), 1);
    }
    assert_eq!(controller.global_in_use(), 0);
    assert_eq!(controller.release_count(), 3);

    let mut expired = controller
        .reserve_with_deadline(partition.clone(), 1, std::time::Instant::now())
        .expect("deadline reserve still holds occupancy");
    assert_eq!(
        expired.commit().expect_err("expired commit rejects"),
        fastmcp_core::AdmissionError::DeadlineExceeded
    );
    assert_eq!(controller.global_in_use(), 1);
    assert_eq!(controller.committed_work(), 0);
    expired.release().expect("release after commit-reject");
    assert_eq!(controller.global_in_use(), 0);

    let peer = fastmcp_core::AdmissionController::with_capacities(snapshot.snapshot(), 2, 2)
        .expect("fairness capacities");
    let left = limit_01_b_partition("tcp:203.0.113.10");
    let right = limit_01_b_partition("tcp:203.0.113.11");
    let mut left_hold = peer
        .reserve(left.clone(), 2)
        .expect("left saturates global");
    assert_eq!(
        peer.reserve(right.clone(), 1)
            .expect_err("saturated global rejects the other partition"),
        fastmcp_core::AdmissionError::GlobalCapacityExceeded {
            requested: 1,
            in_use: 2,
            limit: 2,
        }
    );
    assert_eq!(peer.partition_in_use(&right), 0);
    assert_eq!(peer.partition_in_use(&left), 2);
    left_hold.release().expect("left release frees global");
    let mut right_hold = peer
        .reserve(right.clone(), 1)
        .expect("release admits only the eligible other partition");
    assert_eq!(peer.partition_in_use(&left), 0);
    assert_eq!(peer.partition_in_use(&right), 1);
    assert_eq!(peer.global_in_use(), 1);
    assert_eq!(peer.admission_count(), 2);
    right_hold.release().expect("right release");
    assert_eq!(peer.live_reservation_count(), 0);

    let leak_probe =
        fastmcp_core::AdmissionController::with_capacity(snapshot.snapshot(), 1).expect("capacity one");
    let leak_partition = limit_01_b_partition("tcp:203.0.113.12");
    for cycle in 0..64 {
        let mut reservation = leak_probe
            .reserve(leak_partition.clone(), 1)
            .expect("capacity-one cycle admits");
        assert_eq!(leak_probe.live_reservation_count(), 1);
        reservation.release().expect("capacity-one cycle releases");
        assert_eq!(leak_probe.live_reservation_count(), 0);
        assert_eq!(leak_probe.global_in_use(), 0);
        assert_eq!(leak_probe.release_count(), cycle + 1);
    }

    // -----------------------------------------------------------------------
    // Ordered acceptance rows and the three canonical LIMIT-01 B receipts.
    // -----------------------------------------------------------------------

    use limit_01_rows::{B_GLOBAL_CAPACITY, B_PARTITION_CAPACITY, Counters, Terminal};

    // AC-LIMIT-B-01-RESERVE — numeric floor 6, digest LIMIT01-B-RESERVE-v1 over
    // ordered capacity / request / result / counter fields.
    let reserve_rows = limit_01_rows::run_reserve_rows();
    assert_eq!(
        reserve_rows.len(),
        6,
        "AC-LIMIT-B-01 numeric floor is 6 rows"
    );
    // Tuple: id, binding ceiling, requested, state, diagnostic, global_in_use,
    // partition_in_use, live. The global rows carry two live prefill
    // reservations on OTHER partitions, so their expected live count is the
    // prefill plus this row's own outcome.
    let expected_reserve: [(
        &str,
        &str,
        usize,
        &str,
        Option<fastmcp_core::AdmissionError>,
        usize,
        usize,
        usize,
    ); 6] = [
        // Per-partition ceiling: N-1, N, N+1. No prefill.
        ("LIMIT-B-01.01", "partition", B_PARTITION_CAPACITY - 1, "held", None, 2, 2, 1),
        ("LIMIT-B-01.02", "partition", B_PARTITION_CAPACITY, "held", None, 3, 3, 1),
        (
            "LIMIT-B-01.03",
            "partition",
            B_PARTITION_CAPACITY + 1,
            "none",
            Some(fastmcp_core::AdmissionError::PartitionCapacityExceeded {
                requested: B_PARTITION_CAPACITY + 1,
                in_use: 0,
                limit: B_PARTITION_CAPACITY,
            }),
            0,
            0,
            0,
        ),
        // Controller-wide ceiling with four units prefilled elsewhere across two
        // reservations: N-1, N, N+1.
        ("LIMIT-B-01.04", "global", 1, "held", None, 5, 1, 3),
        ("LIMIT-B-01.05", "global", 2, "held", None, 6, 2, 3),
        (
            "LIMIT-B-01.06",
            "global",
            3,
            "none",
            Some(fastmcp_core::AdmissionError::GlobalCapacityExceeded {
                requested: 3,
                in_use: 4,
                limit: B_GLOBAL_CAPACITY,
            }),
            4,
            0,
            2,
        ),
    ];
    for (index, (id, ceiling, requested, state, diagnostic, global, partition, live)) in
        expected_reserve.into_iter().enumerate()
    {
        let row = &reserve_rows[index];
        assert_eq!(row.id, id, "reserve row {index} is out of acceptance order");
        assert_eq!(row.ceiling, ceiling, "{id}: wrong binding ceiling");
        assert_eq!(row.requested, requested, "{id}: wrong requested units");
        assert_eq!(row.state, state, "{id}: wrong reservation state");
        assert_eq!(row.diagnostic, diagnostic, "{id}: wrong rejection diagnostic");
        assert_eq!(row.after.global_in_use, global, "{id}: wrong global_in_use");
        assert_eq!(
            row.after.partition_in_use, partition,
            "{id}: wrong partition_in_use"
        );
        // Each successful reserve increments each applicable counter exactly
        // once; a refusal retains no reservation of its own.
        assert_eq!(
            row.after.live, live,
            "{id}: wrong live reservation count after the attempt"
        );
        // No attempt on any row has settled yet, so nothing has been released.
        assert_eq!(row.after.release_count, 0, "{id}: nothing may have released");
        assert_eq!(row.after.committed_work, 0, "{id}: reserve must not commit");
    }
    let reserve = limit_01_rows::reserve_receipt(&reserve_rows);
    assert_eq!(reserve.len(), 1 + 6);
    assert_eq!(
        reserve[0],
        format!(
            "LIMIT01-B-RESERVE-v1 rows=6 global={B_GLOBAL_CAPACITY} partition={B_PARTITION_CAPACITY}"
        )
    );

    // AC-LIMIT-B-02-LIFECYCLE — numeric floor 6, digest LIMIT01-B-LIFECYCLE-v1
    // over ordered lifecycle / result / counter fields. All six named terminal
    // rows, including cancellation.
    let lifecycle_rows = limit_01_rows::run_lifecycle_rows();
    assert_eq!(
        lifecycle_rows.len(),
        6,
        "AC-LIMIT-B-02 numeric floor is 6 rows"
    );
    let discharged = Counters {
        global_in_use: 0,
        partition_in_use: 0,
        committed_work: 0,
        release_count: 1,
        live: 0,
    };
    for (index, (id, terminal, state)) in [
        ("LIMIT-B-02.01", Terminal::CommitSuccess, "committed"),
        ("LIMIT-B-02.02", Terminal::CommitReject, "released"),
        ("LIMIT-B-02.03", Terminal::ExplicitRelease, "released"),
        ("LIMIT-B-02.04", Terminal::Cancellation, "cancelled"),
        ("LIMIT-B-02.05", Terminal::Deadline, "deadline-exceeded"),
        ("LIMIT-B-02.06", Terminal::Drop, "dropped"),
    ]
    .into_iter()
    .enumerate()
    {
        let row = &lifecycle_rows[index];
        assert_eq!(row.id, id, "lifecycle row {index} is out of acceptance order");
        assert_eq!(row.terminal, terminal, "{id}: wrong terminal disposition");
        assert_eq!(row.state, state, "{id}: wrong reservation state");
        // Every terminal path releases each charge exactly once: release_count
        // is 1, never 0 (leaked) and never 2 (double-released).
        assert_eq!(
            row.after, discharged,
            "{id}: every terminal path must discharge exactly once"
        );
        // Neither a repeated commit nor a repeated release may be accepted.
        if row.terminal == Terminal::Drop {
            assert_eq!(row.repeated_commit, None);
            assert_eq!(row.repeated_release, None);
        } else {
            assert_eq!(
                row.repeated_commit,
                Some(Err(fastmcp_core::AdmissionError::AlreadySettled)),
                "{id}: a repeated commit must reject"
            );
            assert_eq!(
                row.repeated_release,
                Some(Err(fastmcp_core::AdmissionError::AlreadySettled)),
                "{id}: a repeated release must reject"
            );
        }
    }
    // The cancellation row is present and really exercised the shipped
    // `AdmissionReservation::cancel` entrypoint.
    assert!(
        lifecycle_rows
            .iter()
            .any(|row| row.terminal == Terminal::Cancellation),
        "AC-LIMIT-B-02 requires a cancellation terminal row"
    );
    let lifecycle = limit_01_rows::lifecycle_receipt(&lifecycle_rows);
    assert_eq!(lifecycle.len(), 1 + 6);
    assert_eq!(lifecycle[0], "LIMIT01-B-LIFECYCLE-v1 rows=6");

    // AC-LIMIT-B-03-FAIRNESS — numeric floor 4, digest LIMIT01-B-FAIRNESS-v1
    // over ordered partition / request / outcome / counter fields.
    let fairness_rows = limit_01_rows::run_fairness_rows();
    assert_eq!(
        fairness_rows.len(),
        4,
        "AC-LIMIT-B-03 numeric floor is 4 rows"
    );
    let expected_fairness: [(&str, &str, &str, usize, usize, usize); 4] = [
        // (id, partition, outcome, global, left, right)
        ("LIMIT-B-03.01", "left", "admitted", 2, 2, 0),
        ("LIMIT-B-03.02", "right", "refused", 2, 2, 0),
        ("LIMIT-B-03.03", "right", "admitted", 1, 0, 1),
        ("LIMIT-B-03.04", "right", "refused", 1, 0, 1),
    ];
    for (index, (id, partition, outcome, global, left, right)) in
        expected_fairness.into_iter().enumerate()
    {
        let row = &fairness_rows[index];
        assert_eq!(row.id, id, "fairness row {index} is out of acceptance order");
        assert_eq!(row.partition, partition, "{id}: wrong acting partition");
        assert_eq!(row.outcome, outcome, "{id}: wrong outcome");
        // Saturation never exceeds global N.
        assert!(row.global_in_use <= 2, "{id}: global occupancy exceeded N");
        assert_eq!(row.global_in_use, global, "{id}: wrong global counter");
        assert_eq!(row.left_in_use, left, "{id}: wrong left partition counter");
        assert_eq!(row.right_in_use, right, "{id}: wrong right partition counter");
    }
    // One partition cannot retain another partition's charge: once left
    // releases, its counter is zero even while right holds.
    assert_eq!(fairness_rows[2].left_in_use, 0);
    assert_eq!(fairness_rows[2].right_in_use, 1);
    // The refusals are the typed boundary errors, and they name different
    // ceilings: .02 is refused globally, .04 by the peer's own partition row.
    assert_eq!(
        fairness_rows[1].diagnostic,
        Some(fastmcp_core::AdmissionError::GlobalCapacityExceeded {
            requested: 1,
            in_use: 2,
            limit: 2,
        })
    );
    assert_eq!(
        fairness_rows[3].diagnostic,
        Some(fastmcp_core::AdmissionError::PartitionCapacityExceeded {
            requested: 2,
            in_use: 1,
            limit: 2,
        })
    );
    let fairness = limit_01_rows::fairness_receipt(&fairness_rows);
    assert_eq!(fairness.len(), 1 + 4);
    assert_eq!(fairness[0], "LIMIT01-B-FAIRNESS-v1 rows=4");
}


/// LIMIT-01 B planted negative: one-variable N+1 and second release leave counters unchanged.
#[test]
fn limit_01_b_planted_negative() {
    let snapshot = limit_01_b_limits();
    let controller =
        fastmcp_core::AdmissionController::with_capacities(snapshot.snapshot(), 4, 2).expect("capacities");
    let left = limit_01_b_partition("tcp:203.0.113.10");
    let right = limit_01_b_partition("tcp:203.0.113.11");
    let mut left_hold = controller.reserve(left.clone(), 1).expect("left holds 1");
    let before_global = controller.global_in_use();
    let before_left = controller.partition_in_use(&left);
    let before_right = controller.partition_in_use(&right);
    let before_committed = controller.committed_work();
    let before_releases = controller.release_count();
    let before_admitted = controller.admission_count();
    assert_eq!(
        controller
            .reserve(right.clone(), 3)
            .expect_err("partition N+1 rejects"),
        fastmcp_core::AdmissionError::PartitionCapacityExceeded {
            requested: 3,
            in_use: 0,
            limit: 2,
        }
    );
    assert_eq!(controller.global_in_use(), before_global);
    assert_eq!(controller.partition_in_use(&left), before_left);
    assert_eq!(controller.partition_in_use(&right), before_right);
    assert_eq!(controller.committed_work(), before_committed);
    assert_eq!(controller.release_count(), before_releases);
    assert_eq!(controller.admission_count(), before_admitted);
    assert_eq!(controller.live_reservation_count(), 1);

    left_hold.release().expect("first release");
    let after_first = (
        controller.global_in_use(),
        controller.partition_in_use(&left),
        controller.committed_work(),
        controller.release_count(),
        controller.live_reservation_count(),
        controller.admission_count(),
    );
    assert_eq!(after_first.4, 0, "a released reservation is not retained");
    assert_eq!(
        left_hold
            .release()
            .expect_err("second release is already settled"),
        fastmcp_core::AdmissionError::AlreadySettled
    );
    assert_eq!(
        (
            controller.global_in_use(),
            controller.partition_in_use(&left),
            controller.committed_work(),
            controller.release_count(),
            controller.live_reservation_count(),
            controller.admission_count(),
        ),
        after_first
    );

    // -----------------------------------------------------------------------
    // The canonical receipts are unchanged across the refused one-variable
    // mutation — and are proved sensitive first, so "unchanged" means something.
    // -----------------------------------------------------------------------

    let reserve_before = limit_01_rows::reserve_receipt(&limit_01_rows::run_reserve_rows());
    let lifecycle_before =
        limit_01_rows::lifecycle_receipt(&limit_01_rows::run_lifecycle_rows());
    let fairness_before =
        limit_01_rows::fairness_receipt(&limit_01_rows::run_fairness_rows());

    // SENSITIVITY: perturb exactly one observed field per row set and require
    // the digest to move. A digest that cannot change witnesses nothing.
    let mut perturbed_reserve = limit_01_rows::run_reserve_rows();
    perturbed_reserve[0].after.global_in_use += 1;
    assert_ne!(
        limit_01_rows::reserve_receipt(&perturbed_reserve),
        reserve_before,
        "LIMIT01-B-RESERVE-v1 must observe global_in_use"
    );
    let mut perturbed_lifecycle = limit_01_rows::run_lifecycle_rows();
    perturbed_lifecycle[3].after.release_count += 1;
    assert_ne!(
        limit_01_rows::lifecycle_receipt(&perturbed_lifecycle),
        lifecycle_before,
        "LIMIT01-B-LIFECYCLE-v1 must observe the release counter"
    );
    let mut perturbed_fairness = limit_01_rows::run_fairness_rows();
    perturbed_fairness[1].right_in_use += 1;
    assert_ne!(
        limit_01_rows::fairness_receipt(&perturbed_fairness),
        fairness_before,
        "LIMIT01-B-FAIRNESS-v1 must observe the peer partition counter"
    );

    // THE ONE VARIABLE: on a fresh controller holding the identical prefix, only
    // the requested units move from the partition ceiling N to N+1.
    let probe = fastmcp_core::AdmissionController::with_capacities(snapshot.snapshot(), 4, 2)
        .expect("capacities");
    let probe_partition = limit_01_b_partition("tcp:203.0.113.13");
    let mut at_n = probe
        .reserve(probe_partition.clone(), 2)
        .expect("N still admits, so the refusal below is the one changed variable");
    at_n.release().expect("release the control reservation");
    let refused = probe
        .reserve(probe_partition.clone(), 3)
        .expect_err("N+1 must refuse");
    assert_eq!(
        refused,
        fastmcp_core::AdmissionError::PartitionCapacityExceeded {
            requested: 3,
            in_use: 0,
            limit: 2,
        }
    );
    assert_eq!(probe.live_reservation_count(), 0);

    // Neither counter nor canonical state digest moved.
    assert_eq!(
        limit_01_rows::reserve_receipt(&limit_01_rows::run_reserve_rows()),
        reserve_before,
        "the refused N+1 must leave LIMIT01-B-RESERVE-v1 byte-identical"
    );
    assert_eq!(
        limit_01_rows::lifecycle_receipt(&limit_01_rows::run_lifecycle_rows()),
        lifecycle_before,
        "the refused N+1 must leave LIMIT01-B-LIFECYCLE-v1 byte-identical"
    );
    assert_eq!(
        limit_01_rows::fairness_receipt(&limit_01_rows::run_fairness_rows()),
        fairness_before,
        "the refused N+1 must leave LIMIT01-B-FAIRNESS-v1 byte-identical"
    );
}
