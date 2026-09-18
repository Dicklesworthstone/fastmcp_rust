//! LIMIT-01 A/B ordered acceptance rows and canonical digest receipts.
//!
//! Ported from the crate-internal `#[cfg(test)] mod limit_01_rows` for
//! bd-600a3. The in-crate copy is deliberately left in place; this one exists
//! so the frozen LIMIT-01 IDs can run as EXTERNAL consumers, which `cfg(test)`
//! placement made impossible (PL-3).
//!
//! THREE THINGS DIFFER FROM THE `src/` COPY, and only the first is forced:
//!   1. `crate::` -> `fastmcp_core::`, because this is a separate crate.
//!   2. `pub(crate)` -> `pub` on every item. NOT required — a `mod` inside an
//!      integration target is part of that test binary's own crate, so
//!      `pub(crate)` was already visible to the parent. Incidental, from
//!      scripting the port, and harmless.
//!   3. `.err().expect(..)` -> `.expect_err(..)` at two sites, because
//!      `clippy::err_expect` fires on this target and not on the `cfg(test)`
//!      one. Behaviourally identical; the `src/` copy was resynced to match at
//!      c620d567.
//!
//! An earlier version of this header said "ported verbatim" and "nothing here
//! needed to change but the crate path". Both were false — 70 items changed
//! visibility — and the accurate account lived only in the commit message,
//! where nobody opening this file would find it. Corrected in place rather than
//! deleted, so the claim cannot be re-derived from the file's shape.
//!
//! No API was widened to make this compile: every symbol used here was already
//! public at `fastmcp_core`'s root, and the commit that added this file touches
//! zero `src/` files.
//!
//! Each integration target compiles its own copy of this module, so items
//! used by only one of the two targets are dead code in the other.
#![allow(dead_code)]

//! Ordered acceptance rows and canonical receipts for LIMIT-01 A and B.
//!
//! The LIMIT-01 A and B acceptance criteria each name an ordered subcase range
//! (`LIMIT-A-01.01`..`LIMIT-A-01.06` and so on), a numeric row floor, a tuple of
//! observed fields, and a **canonical digest** built over those ordered fields:
//! `LIMIT01-A-BOUNDS-v1`, `LIMIT01-A-PARTITIONS-v1`, `LIMIT01-A-ARITHMETIC-v1`,
//! `LIMIT01-B-RESERVE-v1`, `LIMIT01-B-LIFECYCLE-v1`, `LIMIT01-B-FAIRNESS-v1`.
//! This module builds those rows and receipts so the floors are literally
//! observable in the source and in the assertion output, matching the shape the
//! LIMIT-01 integration leaf already uses for its own two digests.
//!
//! Everything here is test-only scaffolding, but every observation it records is
//! taken from the **shipped** public limits surface re-exported at the crate
//! root — no `pub(crate)` helper and no `cfg(test)` behaviour is consulted, so
//! the rows cannot prove something the shipped API does not do (PL-3).

use fastmcp_core::{
    AdmissionController, AdmissionError, AdmissionPartition, AdmissionReservation,
    AuthorizationFlowQuotaKey, DEFAULT_CANCELLATION_REASON_MAX_BYTES, DEFAULT_CURSOR_MAX_BYTES,
    DEFAULT_JSON_RPC_MAX_BODY_BYTES, DEFAULT_METADATA_MAX_BYTES, DEFAULT_METADATA_MAX_ENTRIES,
    DEFAULT_URI_MAX_BYTES, PreAuthSourceBucketKey,
    ProtocolLimit, ProtocolLimits, ProtocolLimitsError, QuotaPartitionKey, SealedAdmissionKeyError,
};

/// The documented default snapshot every row starts from.
pub fn documented_limits() -> ProtocolLimits {
    ProtocolLimits::try_new(
        DEFAULT_JSON_RPC_MAX_BODY_BYTES,
        DEFAULT_METADATA_MAX_ENTRIES,
        DEFAULT_METADATA_MAX_BYTES,
        DEFAULT_URI_MAX_BYTES,
        DEFAULT_CANCELLATION_REASON_MAX_BYTES,
        DEFAULT_CURSOR_MAX_BYTES,
    )
    .expect("the documented defaults must admit")
}

/// The six countable catalog rows owned by AC-LIMIT-A-01, in acceptance order.
pub const BOUND_ROW_IDS: [&str; 6] = [
    "LIMIT-A-01.01",
    "LIMIT-A-01.02",
    "LIMIT-A-01.03",
    "LIMIT-A-01.04",
    "LIMIT-A-01.05",
    "LIMIT-A-01.06",
];

/// The ordered catalog rows: acceptance ID, bound, documented default, ceiling.
pub fn bound_rows() -> [(&'static str, ProtocolLimit, usize, usize); 6] {
    [
        (
            BOUND_ROW_IDS[0],
            ProtocolLimit::JsonRpcBodyBytes,
            DEFAULT_JSON_RPC_MAX_BODY_BYTES,
            fastmcp_core::HARD_JSON_RPC_MAX_BODY_BYTES,
        ),
        (
            BOUND_ROW_IDS[1],
            ProtocolLimit::MetadataEntries,
            DEFAULT_METADATA_MAX_ENTRIES as usize,
            fastmcp_core::HARD_METADATA_MAX_ENTRIES as usize,
        ),
        (
            BOUND_ROW_IDS[2],
            ProtocolLimit::MetadataBytes,
            DEFAULT_METADATA_MAX_BYTES,
            fastmcp_core::HARD_METADATA_MAX_BYTES,
        ),
        (
            BOUND_ROW_IDS[3],
            ProtocolLimit::UriBytes,
            DEFAULT_URI_MAX_BYTES,
            fastmcp_core::HARD_URI_MAX_BYTES,
        ),
        (
            BOUND_ROW_IDS[4],
            ProtocolLimit::CancellationReasonBytes,
            DEFAULT_CANCELLATION_REASON_MAX_BYTES,
            fastmcp_core::HARD_CANCELLATION_REASON_MAX_BYTES,
        ),
        (
            BOUND_ROW_IDS[5],
            ProtocolLimit::CursorBytes,
            DEFAULT_CURSOR_MAX_BYTES,
            fastmcp_core::HARD_CURSOR_MAX_BYTES,
        ),
    ]
}

/// Builds the documented configuration with **exactly one** row overridden.
///
/// This is the one-variable machinery shared by the positive (override = the
/// declared hard ceiling, which must admit) and the planted negative (override =
/// ceiling + 1, which must refuse). Every other row keeps its documented value,
/// so a refusal can only be attributed to the single changed variable.
pub fn build_with_override(
    limit: ProtocolLimit,
    value: usize,
) -> Result<ProtocolLimits, ProtocolLimitsError> {
    let pick = |row: ProtocolLimit, documented: usize| -> usize {
        if row == limit { value } else { documented }
    };
    let entries = pick(
        ProtocolLimit::MetadataEntries,
        DEFAULT_METADATA_MAX_ENTRIES as usize,
    );
    let entries = u16::try_from(entries)
        .map_err(|_| ProtocolLimitsError::ExceedsHardCeiling { limit })?;
    ProtocolLimits::builder()
        .json_rpc_max_body_bytes(pick(
            ProtocolLimit::JsonRpcBodyBytes,
            DEFAULT_JSON_RPC_MAX_BODY_BYTES,
        ))
        .metadata_max_entries(entries)
        .metadata_max_bytes(pick(
            ProtocolLimit::MetadataBytes,
            DEFAULT_METADATA_MAX_BYTES,
        ))
        .uri_max_bytes(pick(ProtocolLimit::UriBytes, DEFAULT_URI_MAX_BYTES))
        .cancellation_reason_max_bytes(pick(
            ProtocolLimit::CancellationReasonBytes,
            DEFAULT_CANCELLATION_REASON_MAX_BYTES,
        ))
        .cursor_max_bytes(pick(ProtocolLimit::CursorBytes, DEFAULT_CURSOR_MAX_BYTES))
        .build()
}

// ---------------------------------------------------------------------------
// AC-LIMIT-A-01 — ordered bound rows (numeric floor: 6)
// ---------------------------------------------------------------------------

/// One ordered AC-LIMIT-A-01 row and its four named observed fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundObservation {
    pub id: &'static str,
    /// Observed field: configured default on the accepted snapshot.
    pub configured: usize,
    /// Observed field: declared hard ceiling for the row.
    pub ceiling: usize,
    /// Observed field: immutable snapshot generation.
    pub generation: u64,
    /// Observed field: rejection diagnostic for the ceiling + 1 configuration.
    pub refused_above_ceiling: ProtocolLimitsError,
}

/// Runs the six ordered AC-LIMIT-A-01 rows against the shipped public surface.
pub fn run_bound_rows() -> Vec<BoundObservation> {
    let accepted = documented_limits();
    accepted.validate().expect("the defaults remain valid");
    let snapshot = accepted.snapshot();
    let mut rows = Vec::new();
    for (id, limit, default, ceiling) in bound_rows() {
        // Predicate half one: a value AT the declared ceiling is admitted.
        let at_ceiling =
            build_with_override(limit, ceiling).expect("a value at the hard ceiling must admit");
        assert_eq!(
            at_ceiling
                .configured_units(limit)
                .expect("a countable row reports its units"),
            ceiling,
            "{id}: the accepted configuration must carry the ceiling it was given"
        );
        // Predicate half two: ceiling + 1 is refused, and that is the diagnostic
        // this row records.
        let refused_above_ceiling = build_with_override(limit, ceiling + 1)
            .expect_err("a value above the hard ceiling must refuse");
        rows.push(BoundObservation {
            id,
            configured: snapshot
                .configured_units(limit)
                .expect("a countable row reports its units"),
            ceiling: ProtocolLimits::hard_ceiling(limit)
                .expect("a countable row declares a ceiling"),
            generation: snapshot.generation(),
            refused_above_ceiling,
        });
        assert_eq!(
            rows.last().expect("row just pushed").configured,
            default,
            "{id}: the configured default must match the documented constant"
        );
    }
    rows
}

/// The `LIMIT01-A-BOUNDS-v1` canonical receipt over ordered
/// row ID / default / ceiling / result fields.
pub fn bounds_receipt(rows: &[BoundObservation]) -> Vec<String> {
    let mut receipt = vec![format!(
        "LIMIT01-A-BOUNDS-v1 rows={} generation={}",
        rows.len(),
        rows.first().map_or(0, |row| row.generation)
    )];
    for row in rows {
        receipt.push(format!(
            "{} configured={} ceiling={} generation={} refused={:?}",
            row.id, row.configured, row.ceiling, row.generation, row.refused_above_ceiling
        ));
    }
    receipt
}

// ---------------------------------------------------------------------------
// AC-LIMIT-A-02 — ordered partition rows (numeric floor: 5)
// ---------------------------------------------------------------------------

/// One ordered AC-LIMIT-A-02 row and its four named observed fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionObservation {
    pub id: &'static str,
    /// Observed field: partition discriminant, or `refused` when none was built.
    pub discriminant: &'static str,
    /// Observed field: immutable limits generation alongside the construction.
    pub generation: u64,
    /// Observed field: non-authorizing-key status. Computed, not asserted: this
    /// row re-offers its own raw input to the sealed request-identifier path and
    /// records whether that path refused. If a constructor were ever unsealed,
    /// this flips to `false` and the canonical digest changes.
    pub non_authorizing: bool,
    /// Observed field: constructor result.
    pub result: Result<(), SealedAdmissionKeyError>,
}

/// Probes the sealed path with a row's own raw input.
fn refuses_request_identifier(raw: &str) -> bool {
    matches!(
        AdmissionPartition::try_from_request_identifier(raw),
        Err(SealedAdmissionKeyError::RequestSuppliedIdentifier)
    )
}

/// Runs the five ordered AC-LIMIT-A-02 rows against the shipped public surface.
pub fn run_partition_rows() -> Vec<PartitionObservation> {
    let accepted = documented_limits();
    // The request snapshot taken once, before any partition work.
    let snapshot = accepted.snapshot();
    let mut rows = Vec::new();

    // LIMIT-A-02.01 — unauthenticated transport-observed input stays PreAuth.
    let pre_auth = AdmissionPartition::pre_auth(
        PreAuthSourceBucketKey::from_listener_and_source("mcp.example.test", "tcp:203.0.113.8")
            .expect("a transport-observed source is admitted"),
    );
    assert!(pre_auth.is_pre_auth(), "LIMIT-A-02.01 must remain pre-auth");
    assert!(
        !pre_auth.is_verified(),
        "LIMIT-A-02.01 must not be verified"
    );
    rows.push(PartitionObservation {
        id: "LIMIT-A-02.01",
        discriminant: "PreAuth",
        generation: snapshot.generation(),
        non_authorizing: refuses_request_identifier("tcp:203.0.113.8"),
        result: Ok(()),
    });

    // LIMIT-A-02.02 — verified security facts mint the verified domain.
    let verified = AdmissionPartition::verified(
        QuotaPartitionKey::from_verified_security_facts(
            "static-token",
            1,
            "https://issuer.example.test",
            "https://mcp.example.test/mcp",
            "tenant-a",
            "subject-a",
        )
        .expect("verified security facts mint a partition key"),
    );
    assert!(verified.is_verified(), "LIMIT-A-02.02 must be verified");
    rows.push(PartitionObservation {
        id: "LIMIT-A-02.02",
        discriminant: "Verified",
        generation: snapshot.generation(),
        non_authorizing: refuses_request_identifier("subject-a"),
        result: Ok(()),
    });

    // LIMIT-A-02.03 — a configured pre-token flow is its own domain.
    let flow = AdmissionPartition::authorization_flow(
        AuthorizationFlowQuotaKey::from_configured_flow(
            "https://issuer.example.test",
            "https://mcp.example.test/mcp",
            "registered-client-1",
            "loopback",
            "oauth-authorization-code",
        )
        .expect("a configured flow is admitted"),
    );
    assert!(
        !flow.is_verified() && !flow.is_pre_auth(),
        "LIMIT-A-02.03 is neither verified nor pre-auth"
    );
    rows.push(PartitionObservation {
        id: "LIMIT-A-02.03",
        discriminant: "AuthorizationFlow",
        generation: snapshot.generation(),
        non_authorizing: refuses_request_identifier("registered-client-1"),
        result: Ok(()),
    });

    // LIMIT-A-02.04 — a raw identifier cannot mint a quota partition key.
    let key_refusal = QuotaPartitionKey::try_from_request_identifier("raw-request-id")
        .expect_err("a request-supplied identifier must refuse");
    rows.push(PartitionObservation {
        id: "LIMIT-A-02.04",
        discriminant: "refused",
        generation: snapshot.generation(),
        non_authorizing: refuses_request_identifier("raw-request-id"),
        result: Err(key_refusal),
    });

    // LIMIT-A-02.05 — nor can it manufacture a Verified partition.
    let partition_refusal = AdmissionPartition::try_from_request_identifier("raw-request-id")
        .expect_err("a request-supplied identifier must refuse");
    rows.push(PartitionObservation {
        id: "LIMIT-A-02.05",
        discriminant: "refused",
        generation: snapshot.generation(),
        non_authorizing: refuses_request_identifier("raw-request-id"),
        result: Err(partition_refusal),
    });

    // The request snapshot is immutable for its lifecycle: the generation read
    // after all five rows equals the one captured before the first.
    assert_eq!(
        snapshot, accepted.snapshot(),
        "the request snapshot must be immutable across its lifecycle"
    );
    rows
}

/// The `LIMIT01-A-PARTITIONS-v1` canonical receipt over ordered
/// discriminant / generation / result fields.
pub fn partitions_receipt(rows: &[PartitionObservation]) -> Vec<String> {
    let mut receipt = vec![format!("LIMIT01-A-PARTITIONS-v1 rows={}", rows.len())];
    for row in rows {
        receipt.push(format!(
            "{} discriminant={} generation={} non_authorizing={} result={:?}",
            row.id, row.discriminant, row.generation, row.non_authorizing, row.result
        ));
    }
    receipt
}

// ---------------------------------------------------------------------------
// AC-LIMIT-A-03 — ordered arithmetic rows (numeric floor: 4)
// ---------------------------------------------------------------------------

/// One ordered AC-LIMIT-A-03 row and its four named observed fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArithmeticObservation {
    pub id: &'static str,
    /// Observed field: requested units.
    pub requested: usize,
    /// Observed field: available units on the row.
    pub available: usize,
    /// Observed field: public result.
    pub result: Result<usize, ProtocolLimitsError>,
    /// Observed field: the caller-retained counter after the attempt.
    pub retained: usize,
}

/// Runs the four ordered AC-LIMIT-A-03 rows: N-1, N, N+1, overflow.
///
/// All four share one retained counter so that "no counter wraps" and "a refusal
/// does not advance retained state" are observable across the whole sequence
/// rather than asserted per isolated call.
pub fn run_arithmetic_rows() -> Vec<ArithmeticObservation> {
    let limits = documented_limits();
    let limit = ProtocolLimit::MetadataEntries;
    let available = limits
        .configured_units(limit)
        .expect("a countable row reports its units");
    let mut retained = 0_usize;
    let mut rows = Vec::new();

    for (id, current, additional) in [
        ("LIMIT-A-03.01", 0_usize, available - 1),
        ("LIMIT-A-03.02", 0_usize, available),
        ("LIMIT-A-03.03", available, 1_usize),
        ("LIMIT-A-03.04", usize::MAX, 1_usize),
    ] {
        let result = limits.try_charge(limit, current, additional);
        // A refusal must not advance the caller's retained counter; only an
        // admitted charge does.
        if let Ok(admitted) = result {
            retained = admitted;
        }
        rows.push(ArithmeticObservation {
            id,
            requested: additional,
            available,
            result,
            retained,
        });
    }
    rows
}

/// The `LIMIT01-A-ARITHMETIC-v1` canonical receipt over ordered
/// inputs / results / counters.
pub fn arithmetic_receipt(rows: &[ArithmeticObservation]) -> Vec<String> {
    let mut receipt = vec![format!("LIMIT01-A-ARITHMETIC-v1 rows={}", rows.len())];
    for row in rows {
        receipt.push(format!(
            "{} requested={} available={} result={:?} retained={}",
            row.id, row.requested, row.available, row.result, row.retained
        ));
    }
    receipt
}

// ---------------------------------------------------------------------------
// Shared admission observation for the LIMIT-B rows
// ---------------------------------------------------------------------------

/// The named observed counter tuple for every LIMIT-B row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    pub global_in_use: usize,
    pub partition_in_use: usize,
    pub committed_work: usize,
    pub release_count: usize,
    pub live: usize,
}

pub fn observe(controller: &AdmissionController, partition: &AdmissionPartition) -> Counters {
    Counters {
        global_in_use: controller.global_in_use(),
        partition_in_use: controller.partition_in_use(partition),
        committed_work: controller.committed_work(),
        release_count: controller.release_count(),
        live: controller.live_reservation_count(),
    }
}

pub fn partition_for(source: &str) -> AdmissionPartition {
    AdmissionPartition::pre_auth(
        PreAuthSourceBucketKey::from_listener_and_source("mcp.example.test", source)
            .expect("a transport-observed source is admitted"),
    )
}

/// Global and per-partition ceilings shared by the LIMIT-B reserve rows.
pub const B_GLOBAL_CAPACITY: usize = 6;
pub const B_PARTITION_CAPACITY: usize = 3;

// ---------------------------------------------------------------------------
// AC-LIMIT-B-01 — ordered reserve rows (numeric floor: 6)
// ---------------------------------------------------------------------------

/// One ordered AC-LIMIT-B-01 row and its named observed fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveObservation {
    pub id: &'static str,
    /// Which ceiling this row is exercising.
    pub ceiling: &'static str,
    /// Observed field: requested units.
    pub requested: usize,
    /// Observed field: reservation state after the attempt.
    pub state: &'static str,
    /// Observed field: rejection diagnostic, when the attempt refused.
    pub diagnostic: Option<AdmissionError>,
    /// Observed fields: the counters after the attempt.
    pub after: Counters,
}

/// Runs the six ordered AC-LIMIT-B-01 rows: partition N-1/N/N+1, then global
/// N-1/N/N+1. Each row runs on a fresh controller so its counters are
/// attributable to that row alone.
pub fn run_reserve_rows() -> Vec<ReserveObservation> {
    let snapshot = documented_limits();
    let subject = partition_for("tcp:203.0.113.8");
    let mut rows = Vec::new();

    // Rows .01-.03: the per-partition ceiling binds. N = B_PARTITION_CAPACITY.
    for (id, requested) in [
        ("LIMIT-B-01.01", B_PARTITION_CAPACITY - 1),
        ("LIMIT-B-01.02", B_PARTITION_CAPACITY),
        ("LIMIT-B-01.03", B_PARTITION_CAPACITY + 1),
    ] {
        let controller = AdmissionController::with_capacities(
            snapshot.snapshot(),
            B_GLOBAL_CAPACITY,
            B_PARTITION_CAPACITY,
        )
        .expect("declared capacities are positive");
        let attempt = controller.reserve(subject.clone(), requested);
        let (state, diagnostic, held) = match attempt {
            Ok(reservation) => ("held", None, Some(reservation)),
            Err(error) => ("none", Some(error), None),
        };
        rows.push(ReserveObservation {
            id,
            ceiling: "partition",
            requested,
            state,
            diagnostic,
            after: observe(&controller, &subject),
        });
        drop(held);
    }

    // Rows .04-.06: the controller-wide ceiling binds. Four of the six global
    // units are prefilled on two OTHER partitions, so the subject partition's
    // own ceiling is never the limiting constraint and a refusal is
    // unambiguously global.
    for (id, requested) in [
        ("LIMIT-B-01.04", B_GLOBAL_CAPACITY - 5),
        ("LIMIT-B-01.05", B_GLOBAL_CAPACITY - 4),
        ("LIMIT-B-01.06", B_GLOBAL_CAPACITY - 3),
    ] {
        let controller = AdmissionController::with_capacities(
            snapshot.snapshot(),
            B_GLOBAL_CAPACITY,
            B_PARTITION_CAPACITY,
        )
        .expect("declared capacities are positive");
        let filler_left = partition_for("tcp:203.0.113.20");
        let filler_right = partition_for("tcp:203.0.113.21");
        let left_hold = controller
            .reserve(filler_left, 2)
            .expect("global prefill admits");
        let right_hold = controller
            .reserve(filler_right, 2)
            .expect("global prefill admits");
        assert_eq!(
            controller.global_in_use(),
            4,
            "{id}: the prefill must leave exactly two global units"
        );
        let attempt = controller.reserve(subject.clone(), requested);
        let (state, diagnostic, held) = match attempt {
            Ok(reservation) => ("held", None, Some(reservation)),
            Err(error) => ("none", Some(error), None),
        };
        rows.push(ReserveObservation {
            id,
            ceiling: "global",
            requested,
            state,
            diagnostic,
            after: observe(&controller, &subject),
        });
        drop(held);
        drop(left_hold);
        drop(right_hold);
    }
    rows
}

/// The `LIMIT01-B-RESERVE-v1` canonical receipt over ordered
/// capacity / request / result / counter fields.
pub fn reserve_receipt(rows: &[ReserveObservation]) -> Vec<String> {
    let mut receipt = vec![format!(
        "LIMIT01-B-RESERVE-v1 rows={} global={B_GLOBAL_CAPACITY} partition={B_PARTITION_CAPACITY}",
        rows.len()
    )];
    for row in rows {
        receipt.push(format!(
            "{} ceiling={} requested={} state={} global={} partition={} committed={} released={} diagnostic={:?}",
            row.id,
            row.ceiling,
            row.requested,
            row.state,
            row.after.global_in_use,
            row.after.partition_in_use,
            row.after.committed_work,
            row.after.release_count,
            row.diagnostic,
        ));
    }
    receipt
}

// ---------------------------------------------------------------------------
// AC-LIMIT-B-02 — ordered lifecycle rows (numeric floor: 6)
// ---------------------------------------------------------------------------

/// The six terminal dispositions AC-LIMIT-B-02 names, in acceptance order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    CommitSuccess,
    CommitReject,
    ExplicitRelease,
    Cancellation,
    Deadline,
    Drop,
}

/// One ordered AC-LIMIT-B-02 row and its named observed fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleObservation {
    pub id: &'static str,
    pub terminal: Terminal,
    pub units: usize,
    /// Observed field: reservation state at the terminal event.
    pub state: &'static str,
    /// Observed fields: the counters once the row is fully discharged.
    pub after: Counters,
    /// The result of re-applying a terminal event after settlement. `None` only
    /// for the drop row, whose reservation no longer exists to re-apply one to.
    pub repeated_commit: Option<Result<(), AdmissionError>>,
    pub repeated_release: Option<Result<(), AdmissionError>>,
}

/// Runs the six ordered AC-LIMIT-B-02 rows, one fresh controller per row.
///
/// Every row also re-applies BOTH terminal events after settlement, because the
/// acceptance predicate is "repeated commit **or** release cannot decrement or
/// increment any counter again" — proving only the repeated release would leave
/// half the predicate unproven.
pub fn run_lifecycle_rows() -> Vec<LifecycleObservation> {
    const UNITS: usize = 2;
    let snapshot = documented_limits();
    let subject = partition_for("tcp:203.0.113.8");
    let mut rows = Vec::new();

    for (id, terminal) in [
        ("LIMIT-B-02.01", Terminal::CommitSuccess),
        ("LIMIT-B-02.02", Terminal::CommitReject),
        ("LIMIT-B-02.03", Terminal::ExplicitRelease),
        ("LIMIT-B-02.04", Terminal::Cancellation),
        ("LIMIT-B-02.05", Terminal::Deadline),
        ("LIMIT-B-02.06", Terminal::Drop),
    ] {
        let controller = AdmissionController::with_capacities(
            snapshot.snapshot(),
            B_GLOBAL_CAPACITY,
            B_PARTITION_CAPACITY,
        )
        .expect("declared capacities are positive");

        let mut settled: Option<AdmissionReservation> = None;
        let state = match terminal {
            Terminal::CommitSuccess => {
                let mut reservation = controller
                    .reserve(subject.clone(), UNITS)
                    .expect("the commit-success row admits");
                reservation.commit().expect("commit transfers the charge");
                assert_eq!(
                    controller.committed_work(),
                    UNITS,
                    "{id}: commit must transfer exactly the reserved units"
                );
                reservation.release().expect("committed work releases once");
                settled = Some(reservation);
                "committed"
            }
            Terminal::CommitReject => {
                let mut reservation = controller
                    .reserve(subject.clone(), UNITS)
                    .expect("the commit-reject row admits");
                reservation.release().expect("release before commit");
                assert_eq!(
                    reservation.commit().expect_err("a settled commit rejects"),
                    AdmissionError::AlreadySettled,
                    "{id}: committing a settled reservation must reject"
                );
                settled = Some(reservation);
                "released"
            }
            Terminal::ExplicitRelease => {
                let mut reservation = controller
                    .reserve(subject.clone(), UNITS)
                    .expect("the explicit-release row admits");
                reservation.release().expect("explicit release discharges");
                settled = Some(reservation);
                "released"
            }
            Terminal::Cancellation => {
                let mut reservation = controller
                    .reserve(subject.clone(), UNITS)
                    .expect("the cancellation row admits");
                assert_eq!(
                    controller.global_in_use(),
                    UNITS,
                    "{id}: the cancellation row must actually hold a charge first"
                );
                reservation
                    .cancel()
                    .expect("cancel discharges a held reservation");
                settled = Some(reservation);
                "cancelled"
            }
            Terminal::Deadline => {
                let mut reservation = controller
                    .reserve_with_deadline(subject.clone(), UNITS, std::time::Instant::now())
                    .expect("the deadline row admits and holds occupancy");
                assert_eq!(
                    reservation.commit().expect_err("an expired commit rejects"),
                    AdmissionError::DeadlineExceeded,
                    "{id}: an expired reservation must refuse its commit"
                );
                assert_eq!(
                    controller.global_in_use(),
                    UNITS,
                    "{id}: a refused commit must not release the charge"
                );
                reservation
                    .release()
                    .expect("release after a refused commit");
                settled = Some(reservation);
                "deadline-exceeded"
            }
            Terminal::Drop => {
                {
                    let _dropped = controller
                        .reserve(subject.clone(), UNITS)
                        .expect("the drop row admits");
                    assert_eq!(
                        controller.global_in_use(),
                        UNITS,
                        "{id}: the drop row must hold a charge before the scope ends"
                    );
                }
                "dropped"
            }
        };

        let after = observe(&controller, &subject);
        let (repeated_commit, repeated_release) = match settled.as_mut() {
            Some(reservation) => (
                Some(reservation.commit()),
                Some(reservation.release()),
            ),
            None => (None, None),
        };
        assert_eq!(
            observe(&controller, &subject),
            after,
            "{id}: re-applying a terminal event must not move any counter"
        );

        rows.push(LifecycleObservation {
            id,
            terminal,
            units: UNITS,
            state,
            after,
            repeated_commit,
            repeated_release,
        });
        drop(settled);
    }
    rows
}

/// The `LIMIT01-B-LIFECYCLE-v1` canonical receipt over ordered
/// lifecycle / result / counter fields.
pub fn lifecycle_receipt(rows: &[LifecycleObservation]) -> Vec<String> {
    let mut receipt = vec![format!("LIMIT01-B-LIFECYCLE-v1 rows={}", rows.len())];
    for row in rows {
        receipt.push(format!(
            "{} terminal={:?} units={} state={} global={} partition={} committed={} released={} repeat_commit={:?} repeat_release={:?}",
            row.id,
            row.terminal,
            row.units,
            row.state,
            row.after.global_in_use,
            row.after.partition_in_use,
            row.after.committed_work,
            row.after.release_count,
            row.repeated_commit,
            row.repeated_release,
        ));
    }
    receipt
}

// ---------------------------------------------------------------------------
// AC-LIMIT-B-03 — ordered fairness rows (numeric floor: 4)
// ---------------------------------------------------------------------------

/// One ordered AC-LIMIT-B-03 row and its named observed fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairnessObservation {
    pub id: &'static str,
    /// Which partition made the attempt.
    pub partition: &'static str,
    /// Observed field: requested charge.
    pub requested: usize,
    /// Observed field: the public outcome.
    pub outcome: &'static str,
    /// Observed field: rejection diagnostic, when the attempt refused.
    pub diagnostic: Option<AdmissionError>,
    /// Observed field: global counter after the attempt.
    pub global_in_use: usize,
    /// Observed field: left partition counter after the attempt.
    pub left_in_use: usize,
    /// Observed field: right partition counter after the attempt.
    pub right_in_use: usize,
    /// Observed field: release count after the attempt.
    pub release_count: usize,
}

/// Runs the four ordered AC-LIMIT-B-03 rows across one saturated global row.
///
/// Fairness is inherently sequential, so these four rows share one controller:
/// row `.03` is only meaningful because row `.01` saturated the global ceiling
/// and row `.02` was refused against it.
pub fn run_fairness_rows() -> Vec<FairnessObservation> {
    const GLOBAL: usize = 2;
    const PARTITION: usize = 2;
    let snapshot = documented_limits();
    let controller = AdmissionController::with_capacities(snapshot.snapshot(), GLOBAL, PARTITION)
        .expect("declared capacities are positive");
    let left = partition_for("tcp:203.0.113.10");
    let right = partition_for("tcp:203.0.113.11");
    let mut rows = Vec::new();

    let record =
        |id: &'static str,
         partition: &'static str,
         requested: usize,
         outcome: &'static str,
         diagnostic: Option<AdmissionError>,
         controller: &AdmissionController| FairnessObservation {
            id,
            partition,
            requested,
            outcome,
            diagnostic,
            global_in_use: controller.global_in_use(),
            left_in_use: controller.partition_in_use(&left),
            right_in_use: controller.partition_in_use(&right),
            release_count: controller.release_count(),
        };

    // LIMIT-B-03.01 — left saturates the global ceiling.
    let mut left_hold = controller
        .reserve(left.clone(), GLOBAL)
        .expect("left saturates the global row");
    rows.push(record(
        "LIMIT-B-03.01",
        "left",
        GLOBAL,
        "admitted",
        None,
        &controller,
    ));

    // LIMIT-B-03.02 — saturation never exceeds global N: the peer is refused,
    // and its own partition counter is untouched by the refusal.
    let refusal = controller
        .reserve(right.clone(), 1)
        .expect_err("a saturated global row refuses the peer partition");
    rows.push(record(
        "LIMIT-B-03.02",
        "right",
        1,
        "refused",
        Some(refusal),
        &controller,
    ));

    // LIMIT-B-03.03 — a release admits only a currently eligible reservation,
    // and one partition cannot retain another partition's charge.
    left_hold.release().expect("left releases its charge");
    let mut right_hold = controller
        .reserve(right.clone(), 1)
        .expect("the freed global units admit the eligible peer");
    rows.push(record(
        "LIMIT-B-03.03",
        "right",
        1,
        "admitted",
        None,
        &controller,
    ));

    // LIMIT-B-03.04 — one variable moves: only the requested partition charge
    // rises above the peer's remaining partition N.
    let over_partition = controller
        .reserve(right.clone(), PARTITION)
        .expect_err("a charge above the remaining partition ceiling refuses");
    rows.push(record(
        "LIMIT-B-03.04",
        "right",
        PARTITION,
        "refused",
        Some(over_partition),
        &controller,
    ));

    right_hold.release().expect("right releases its charge");
    rows
}

/// The `LIMIT01-B-FAIRNESS-v1` canonical receipt over ordered
/// partition / request / outcome / counter fields.
pub fn fairness_receipt(rows: &[FairnessObservation]) -> Vec<String> {
    let mut receipt = vec![format!("LIMIT01-B-FAIRNESS-v1 rows={}", rows.len())];
    for row in rows {
        receipt.push(format!(
            "{} partition={} requested={} outcome={} global={} left={} right={} released={} diagnostic={:?}",
            row.id,
            row.partition,
            row.requested,
            row.outcome,
            row.global_in_use,
            row.left_in_use,
            row.right_in_use,
            row.release_count,
            row.diagnostic,
        ));
    }
    receipt
}
