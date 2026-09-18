//! LIMIT-01 integration join (bd-mcp-limit-01-integration-s0b9).
//!
//! This is an **external** consumer of the published `fastmcp-rust` facade: it
//! reaches the LIMIT-01 surface exactly the way a downstream crate does, via
//! `use fastmcp_rust::...`, and never through `use super` or any `pub(crate)`
//! path. `cfg(test)` behaviour inside the facade cannot prove shipped
//! behaviour (PL-3), so every observation below is taken through the shipped
//! public entrypoints named by the frozen acceptance criteria:
//! [`ProtocolLimits`], [`AdmissionPartition`], [`AdmissionController::reserve`],
//! [`AdmissionReservation::commit`], and [`AdmissionReservation::release`].
//!
//! Both acceptance rows are driven from an ordered `const` case table so the
//! numeric floors are literally observable in the source and in the assertion
//! output: AC-LIMIT-I-01 runs `LIMIT-I-01.01`..`LIMIT-I-01.06` (floor 6) and
//! AC-LIMIT-I-02 runs `LIMIT-I-02.01`..`LIMIT-I-02.05` (floor 5). Each row
//! records the acceptance's named observed fields — public result, snapshot
//! generation, `global_in_use`, `partition_in_use`, the committed-work counter
//! and the release counter — and every planted negative changes exactly one
//! variable and proves the retained state byte-for-byte unchanged.
//!
//! No-claim boundary: this leaf does not establish parent completion,
//! aggregate MCP 2026-07-28 support, MCP 2024-11-05 preservation, profile
//! maturity, conformance, publication, or release readiness.

#![forbid(unsafe_code)]

use std::time::Instant;

use fastmcp_rust::{
    AdmissionController, AdmissionError, AdmissionPartition, AdmissionReservation,
    AuthorizationFlowQuotaKey, DEFAULT_CANCELLATION_REASON_MAX_BYTES, DEFAULT_CURSOR_MAX_BYTES,
    DEFAULT_JSON_RPC_MAX_BODY_BYTES, DEFAULT_METADATA_MAX_BYTES, DEFAULT_METADATA_MAX_ENTRIES,
    DEFAULT_URI_MAX_BYTES, HARD_METADATA_MAX_ENTRIES, PROTOCOL_LIMITS_INITIAL_GENERATION,
    PreAuthSourceBucketKey, ProtocolLimit, ProtocolLimits, ProtocolLimitsBuilder,
    ProtocolLimitsError, QuotaPartitionKey, SealedAdmissionKeyError,
};

/// Controller-wide ceiling shared by every ordered subcase.
const GLOBAL_CAPACITY: usize = 6;
/// Per-partition ceiling shared by every ordered subcase.
const PARTITION_CAPACITY: usize = 3;

// ---------------------------------------------------------------------------
// Shared public-surface helpers
// ---------------------------------------------------------------------------

/// The accepted LIMIT-A bounds catalog, built through the shipped public
/// builder with the documented default rows.
fn documented_limits() -> ProtocolLimits {
    ProtocolLimits::builder()
        .json_rpc_max_body_bytes(DEFAULT_JSON_RPC_MAX_BODY_BYTES)
        .metadata_max_entries(DEFAULT_METADATA_MAX_ENTRIES)
        .metadata_max_bytes(DEFAULT_METADATA_MAX_BYTES)
        .uri_max_bytes(DEFAULT_URI_MAX_BYTES)
        .cancellation_reason_max_bytes(DEFAULT_CANCELLATION_REASON_MAX_BYTES)
        .cursor_max_bytes(DEFAULT_CURSOR_MAX_BYTES)
        .build()
        .expect("the shipped public builder must admit the documented default bounds")
}

/// The six configured LIMIT-A catalog rows this leaf joins into LIMIT-B.
fn configured_bound_rows() -> [(ProtocolLimit, usize); 6] {
    [
        (
            ProtocolLimit::JsonRpcBodyBytes,
            DEFAULT_JSON_RPC_MAX_BODY_BYTES,
        ),
        (
            ProtocolLimit::MetadataEntries,
            usize::from(DEFAULT_METADATA_MAX_ENTRIES),
        ),
        (ProtocolLimit::MetadataBytes, DEFAULT_METADATA_MAX_BYTES),
        (ProtocolLimit::UriBytes, DEFAULT_URI_MAX_BYTES),
        (
            ProtocolLimit::CancellationReasonBytes,
            DEFAULT_CANCELLATION_REASON_MAX_BYTES,
        ),
        (ProtocolLimit::CursorBytes, DEFAULT_CURSOR_MAX_BYTES),
    ]
}

/// The three shipped public admission domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartitionKind {
    PreAuth,
    Verified,
    AuthorizationFlow,
}

/// Builds one partition through its public, non-request-derived constructor.
fn partition_for(kind: PartitionKind) -> AdmissionPartition {
    match kind {
        PartitionKind::PreAuth => AdmissionPartition::pre_auth(
            PreAuthSourceBucketKey::from_listener_and_source("mcp.example.test", "tcp:203.0.113.8")
                .expect("listener domain plus transport-observed source mints a pre-auth bucket"),
        ),
        PartitionKind::Verified => AdmissionPartition::verified(
            QuotaPartitionKey::from_verified_security_facts(
                "org.fastmcp.provider",
                1,
                "https://auth.example.test",
                "mcp://servers/main",
                "tenant-1",
                "subject-user-42",
            )
            .expect("verified security facts mint a verified quota partition"),
        ),
        PartitionKind::AuthorizationFlow => AdmissionPartition::authorization_flow(
            AuthorizationFlowQuotaKey::from_configured_flow(
                "https://auth.example.test",
                "mcp://servers/main",
                "client-reg-1",
                "redirect-loopback",
                "auth-profile-modern",
            )
            .expect("configured flow facts mint an authorization-flow quota key"),
        ),
    }
}

/// The acceptance's named observed fields for one partition, read back through
/// the shipped public controller accessors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Observed {
    generation: u64,
    global_in_use: usize,
    partition_in_use: usize,
    committed_work: usize,
    release_count: usize,
    admission_count: usize,
    live_reservations: usize,
}

fn observe(controller: &AdmissionController, partition: &AdmissionPartition) -> Observed {
    Observed {
        generation: controller.limits().generation(),
        global_in_use: controller.global_in_use(),
        partition_in_use: controller.partition_in_use(partition),
        committed_work: controller.committed_work(),
        release_count: controller.release_count(),
        admission_count: controller.admission_count(),
        live_reservations: controller.live_reservation_count(),
    }
}

/// Every mutable admission field, across all three domains at once. Used by the
/// planted negatives for byte-for-byte unchanged-state proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FullState {
    generation: u64,
    global_in_use: usize,
    pre_auth_in_use: usize,
    verified_in_use: usize,
    authorization_flow_in_use: usize,
    committed_work: usize,
    release_count: usize,
    admission_count: usize,
    live_reservations: usize,
}

fn full_state(controller: &AdmissionController) -> FullState {
    FullState {
        generation: controller.limits().generation(),
        global_in_use: controller.global_in_use(),
        pre_auth_in_use: controller.partition_in_use(&partition_for(PartitionKind::PreAuth)),
        verified_in_use: controller.partition_in_use(&partition_for(PartitionKind::Verified)),
        authorization_flow_in_use: controller
            .partition_in_use(&partition_for(PartitionKind::AuthorizationFlow)),
        committed_work: controller.committed_work(),
        release_count: controller.release_count(),
        admission_count: controller.admission_count(),
        live_reservations: controller.live_reservation_count(),
    }
}

// ---------------------------------------------------------------------------
// AC-LIMIT-I-01 — ordered public-join subcases (numeric floor: 6 rows)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedAdmission {
    Admitted,
    Refused(AdmissionError),
}

/// One ordered AC-LIMIT-I-01 subcase.
///
/// `prefill` charges other partitions before the subject reserve, so the same
/// uniform row shape can express both the per-partition ceiling and the global
/// ceiling. Rows `.02`/`.03` and `.05`/`.06` are one-variable pairs: only
/// `requested` moves from `N` to `N + 1`.
#[derive(Debug, Clone, Copy)]
struct PublicJoinCase {
    id: &'static str,
    prefill: &'static [(PartitionKind, usize)],
    subject: PartitionKind,
    requested: usize,
    expected: ExpectedAdmission,
}

/// Prefill shared by the global-ceiling rows: 4 of the 6 global units are held
/// on two partitions that are not the subject, leaving `N = 2` admissible.
const GLOBAL_PREFILL: &[(PartitionKind, usize)] = &[
    (PartitionKind::PreAuth, 2),
    (PartitionKind::AuthorizationFlow, 2),
];

const PUBLIC_JOIN_CASES: [PublicJoinCase; 6] = [
    // Per-partition ceiling, N = PARTITION_CAPACITY = 3.
    PublicJoinCase {
        id: "LIMIT-I-01.01",
        prefill: &[],
        subject: PartitionKind::PreAuth,
        requested: PARTITION_CAPACITY - 1,
        expected: ExpectedAdmission::Admitted,
    },
    PublicJoinCase {
        id: "LIMIT-I-01.02",
        prefill: &[],
        subject: PartitionKind::PreAuth,
        requested: PARTITION_CAPACITY,
        expected: ExpectedAdmission::Admitted,
    },
    // One-variable negative against `.02`: only `requested` moves N -> N + 1.
    PublicJoinCase {
        id: "LIMIT-I-01.03",
        prefill: &[],
        subject: PartitionKind::PreAuth,
        requested: PARTITION_CAPACITY + 1,
        expected: ExpectedAdmission::Refused(AdmissionError::PartitionCapacityExceeded {
            requested: PARTITION_CAPACITY + 1,
            in_use: 0,
            limit: PARTITION_CAPACITY,
        }),
    },
    // Controller-wide ceiling, N = GLOBAL_CAPACITY - 4 = 2.
    PublicJoinCase {
        id: "LIMIT-I-01.04",
        prefill: GLOBAL_PREFILL,
        subject: PartitionKind::Verified,
        requested: GLOBAL_CAPACITY - 5,
        expected: ExpectedAdmission::Admitted,
    },
    PublicJoinCase {
        id: "LIMIT-I-01.05",
        prefill: GLOBAL_PREFILL,
        subject: PartitionKind::Verified,
        requested: GLOBAL_CAPACITY - 4,
        expected: ExpectedAdmission::Admitted,
    },
    // One-variable negative against `.05`: only `requested` moves N -> N + 1.
    PublicJoinCase {
        id: "LIMIT-I-01.06",
        prefill: GLOBAL_PREFILL,
        subject: PartitionKind::Verified,
        requested: GLOBAL_CAPACITY - 3,
        expected: ExpectedAdmission::Refused(AdmissionError::GlobalCapacityExceeded {
            requested: GLOBAL_CAPACITY - 3,
            in_use: 4,
            limit: GLOBAL_CAPACITY,
        }),
    },
];

/// The observations produced by one executed AC-LIMIT-I-01 subcase.
#[derive(Debug, Clone, Copy)]
struct PublicJoinRow {
    id: &'static str,
    requested: usize,
    result: Result<(), AdmissionError>,
    before: Observed,
    after_attempt: Observed,
    after_commit: Option<Observed>,
    after_release: Option<Observed>,
}

fn run_public_join_case(case: &PublicJoinCase) -> PublicJoinRow {
    let accepted = documented_limits();
    let controller = AdmissionController::with_capacities(
        accepted.snapshot(),
        GLOBAL_CAPACITY,
        PARTITION_CAPACITY,
    )
    .expect("the public controller must admit the configured capacities");
    let subject = partition_for(case.subject);

    // Charge the non-subject partitions and hold those charges live for the
    // whole subcase, so the subject reserve sees the intended occupancy.
    let mut prefill_holds = Vec::new();
    for (kind, units) in case.prefill {
        assert_ne!(
            *kind, case.subject,
            "{}: prefill must not touch the subject partition",
            case.id
        );
        prefill_holds.push(
            controller
                .reserve(partition_for(*kind), *units)
                .expect("prefill reserve must be admitted"),
        );
    }

    let before = observe(&controller, &subject);
    let attempt = controller.reserve(subject.clone(), case.requested);
    let after_attempt = observe(&controller, &subject);

    let row = match (attempt, case.expected) {
        (Ok(mut reservation), ExpectedAdmission::Admitted) => {
            reservation
                .commit()
                .unwrap_or_else(|error| panic!("{}: commit must succeed, got {error:?}", case.id));
            let after_commit = observe(&controller, &subject);

            reservation
                .release()
                .unwrap_or_else(|error| panic!("{}: release must succeed, got {error:?}", case.id));
            let after_release = observe(&controller, &subject);

            // No later terminal event may reopen or recharge the reservation.
            assert_eq!(
                reservation.release(),
                Err(AdmissionError::AlreadySettled),
                "{}: a duplicate release must refuse",
                case.id
            );
            assert_eq!(
                reservation.commit(),
                Err(AdmissionError::AlreadySettled),
                "{}: a commit after release must refuse",
                case.id
            );
            assert_eq!(
                observe(&controller, &subject),
                after_release,
                "{}: duplicate terminal events must leave every counter unchanged",
                case.id
            );

            PublicJoinRow {
                id: case.id,
                requested: case.requested,
                result: Ok(()),
                before,
                after_attempt,
                after_commit: Some(after_commit),
                after_release: Some(after_release),
            }
        }
        (Err(error), ExpectedAdmission::Refused(expected)) => {
            assert_eq!(error, expected, "{}: typed refusal mismatch", case.id);
            PublicJoinRow {
                id: case.id,
                requested: case.requested,
                result: Err(error),
                before,
                after_attempt,
                after_commit: None,
                after_release: None,
            }
        }
        (Ok(_), ExpectedAdmission::Refused(expected)) => panic!(
            "{}: reserve of {} units was admitted but must refuse with {expected:?}",
            case.id, case.requested
        ),
        (Err(error), ExpectedAdmission::Admitted) => panic!(
            "{}: reserve of {} units must be admitted but refused with {error:?}",
            case.id, case.requested
        ),
    };

    drop(prefill_holds);
    row
}

fn run_public_join_rows() -> Vec<PublicJoinRow> {
    PUBLIC_JOIN_CASES.iter().map(run_public_join_case).collect()
}

/// Asserts that `negative` differs from `positive` in exactly one variable:
/// the requested unit count, moved from `N` to `N + 1`.
fn assert_one_variable_unit_step(positive: &PublicJoinCase, negative: &PublicJoinCase) {
    assert_eq!(
        positive.subject, negative.subject,
        "{} -> {}: the subject partition must be the only-unchanged control",
        positive.id, negative.id
    );
    assert_eq!(
        positive.prefill, negative.prefill,
        "{} -> {}: the prefill occupancy must not change",
        positive.id, negative.id
    );
    assert_eq!(
        negative.requested,
        positive.requested + 1,
        "{} -> {}: only the requested units may move, by exactly one",
        positive.id,
        negative.id
    );
    assert_eq!(positive.expected, ExpectedAdmission::Admitted);
    assert!(matches!(negative.expected, ExpectedAdmission::Refused(_)));
}

#[test]
fn limit_01_integration_public_join() {
    let rows = run_public_join_rows();

    // Numeric floor: six ordered rows, observable as six rows.
    assert_eq!(
        rows.len(),
        PUBLIC_JOIN_CASES.len(),
        "every declared AC-LIMIT-I-01 subcase must execute"
    );
    assert_eq!(
        rows.len(),
        6,
        "AC-LIMIT-I-01 numeric floor is 6 ordered rows"
    );
    let ids: Vec<&str> = rows.iter().map(|row| row.id).collect();
    assert_eq!(
        ids,
        vec![
            "LIMIT-I-01.01",
            "LIMIT-I-01.02",
            "LIMIT-I-01.03",
            "LIMIT-I-01.04",
            "LIMIT-I-01.05",
            "LIMIT-I-01.06",
        ],
        "AC-LIMIT-I-01 subcases must run in the frozen order"
    );

    // The one-variable negatives change only the requested units.
    assert_one_variable_unit_step(&PUBLIC_JOIN_CASES[1], &PUBLIC_JOIN_CASES[2]);
    assert_one_variable_unit_step(&PUBLIC_JOIN_CASES[4], &PUBLIC_JOIN_CASES[5]);

    let mut admitted = 0_usize;
    let mut refused = 0_usize;

    for row in &rows {
        // Snapshot generation is one of the named observed fields and must be
        // the initial generation at every observation point.
        for observed in [
            Some(row.before),
            Some(row.after_attempt),
            row.after_commit,
            row.after_release,
        ]
        .into_iter()
        .flatten()
        {
            assert_eq!(
                observed.generation, PROTOCOL_LIMITS_INITIAL_GENERATION,
                "{}: the accepted snapshot generation must never move",
                row.id
            );
        }

        match row.result {
            Ok(()) => {
                admitted += 1;
                let after_commit = row
                    .after_commit
                    .expect("an admitted row must record a post-commit observation");
                let after_release = row
                    .after_release
                    .expect("an admitted row must record a post-release observation");

                // Reserve charges occupancy and nothing else.
                assert_eq!(
                    row.after_attempt.global_in_use,
                    row.before.global_in_use + row.requested,
                    "{}: reserve must charge the global counter by the requested units",
                    row.id
                );
                assert_eq!(
                    row.after_attempt.partition_in_use,
                    row.before.partition_in_use + row.requested,
                    "{}: reserve must charge the partition counter by the requested units",
                    row.id
                );
                assert_eq!(
                    row.after_attempt.committed_work, row.before.committed_work,
                    "{}: reserve alone must not move committed work",
                    row.id
                );
                assert_eq!(
                    row.after_attempt.release_count, row.before.release_count,
                    "{}: reserve alone must not move the release counter",
                    row.id
                );

                // Commit moves work exactly once and never duplicates occupancy.
                assert_eq!(
                    after_commit.committed_work,
                    row.before.committed_work + row.requested,
                    "{}: commit must move exactly the requested units into committed work",
                    row.id
                );
                assert_eq!(
                    after_commit.global_in_use, row.after_attempt.global_in_use,
                    "{}: commit must not duplicate global occupancy",
                    row.id
                );
                assert_eq!(
                    after_commit.partition_in_use, row.after_attempt.partition_in_use,
                    "{}: commit must not duplicate partition occupancy",
                    row.id
                );

                // Release is exact-once and returns every counter to its pre-reserve value.
                assert_eq!(
                    after_release.global_in_use, row.before.global_in_use,
                    "{}: release must return the global counter to its pre-reserve value",
                    row.id
                );
                assert_eq!(
                    after_release.partition_in_use, row.before.partition_in_use,
                    "{}: release must return the partition counter to its pre-reserve value",
                    row.id
                );
                assert_eq!(
                    after_release.committed_work, row.before.committed_work,
                    "{}: release must return committed work to its pre-reserve value",
                    row.id
                );
                assert_eq!(
                    after_release.release_count,
                    row.before.release_count + 1,
                    "{}: the terminal path must release exactly once",
                    row.id
                );
                assert_eq!(
                    after_release.live_reservations, row.before.live_reservations,
                    "{}: the settled reservation must not stay live",
                    row.id
                );
                assert_eq!(
                    after_release.admission_count,
                    row.before.admission_count + 1,
                    "{}: exactly one admission may be recorded",
                    row.id
                );
            }
            Err(_) => {
                refused += 1;
                // Refusal happens before any consumer dispatch: the whole
                // observed tuple is byte-for-byte unchanged.
                assert_eq!(
                    row.after_attempt, row.before,
                    "{}: a refused reserve must leave every observed counter unchanged",
                    row.id
                );
                assert!(
                    row.after_commit.is_none() && row.after_release.is_none(),
                    "{}: a refused reserve must not reach commit or release",
                    row.id
                );
            }
        }
    }

    assert_eq!(admitted, 4, "rows .01, .02, .04 and .05 admit at N-1 and N");
    assert_eq!(refused, 2, "rows .03 and .06 refuse at N+1");
}

// ---------------------------------------------------------------------------
// AC-LIMIT-I-02 — ordered lifecycle subcases (numeric floor: 5 rows)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleTerminal {
    Success,
    Cancellation,
    Deadline,
    CommitFailure,
    RepeatedTerminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleEvent {
    Commit,
    Release,
    Cancel,
}

/// One ordered AC-LIMIT-I-02 subcase. The `script` is the full ordered list of
/// public lifecycle events applied after the reserve, each paired with the
/// public result it must produce.
#[derive(Debug, Clone, Copy)]
struct LifecycleCase {
    id: &'static str,
    terminal: LifecycleTerminal,
    units: usize,
    expired_deadline: bool,
    script: &'static [(LifecycleEvent, Result<(), AdmissionError>)],
}

const LIFECYCLE_CASES: [LifecycleCase; 5] = [
    LifecycleCase {
        id: "LIMIT-I-02.01",
        terminal: LifecycleTerminal::Success,
        units: 2,
        expired_deadline: false,
        script: &[
            (LifecycleEvent::Commit, Ok(())),
            (LifecycleEvent::Release, Ok(())),
            // One-variable negative: only a duplicate terminal event is added.
            (LifecycleEvent::Release, Err(AdmissionError::AlreadySettled)),
        ],
    },
    LifecycleCase {
        id: "LIMIT-I-02.02",
        terminal: LifecycleTerminal::Cancellation,
        units: 2,
        expired_deadline: false,
        script: &[
            (LifecycleEvent::Cancel, Ok(())),
            (LifecycleEvent::Commit, Err(AdmissionError::AlreadySettled)),
        ],
    },
    LifecycleCase {
        id: "LIMIT-I-02.03",
        terminal: LifecycleTerminal::Deadline,
        units: 2,
        expired_deadline: true,
        script: &[
            (
                LifecycleEvent::Commit,
                Err(AdmissionError::DeadlineExceeded),
            ),
            (LifecycleEvent::Release, Ok(())),
            (LifecycleEvent::Commit, Err(AdmissionError::AlreadySettled)),
        ],
    },
    LifecycleCase {
        id: "LIMIT-I-02.04",
        terminal: LifecycleTerminal::CommitFailure,
        units: 2,
        expired_deadline: false,
        script: &[
            (LifecycleEvent::Release, Ok(())),
            (LifecycleEvent::Commit, Err(AdmissionError::AlreadySettled)),
            (LifecycleEvent::Release, Err(AdmissionError::AlreadySettled)),
        ],
    },
    LifecycleCase {
        id: "LIMIT-I-02.05",
        terminal: LifecycleTerminal::RepeatedTerminal,
        units: 2,
        expired_deadline: false,
        script: &[
            (LifecycleEvent::Commit, Ok(())),
            (LifecycleEvent::Release, Ok(())),
            // Four further terminal events on an already-settled reservation.
            (LifecycleEvent::Release, Err(AdmissionError::AlreadySettled)),
            (LifecycleEvent::Cancel, Err(AdmissionError::AlreadySettled)),
            (LifecycleEvent::Commit, Err(AdmissionError::AlreadySettled)),
            (LifecycleEvent::Release, Err(AdmissionError::AlreadySettled)),
        ],
    },
];

#[derive(Debug, Clone, Copy)]
struct LifecycleStep {
    event: LifecycleEvent,
    result: Result<(), AdmissionError>,
    observed: Observed,
}

#[derive(Debug, Clone)]
struct LifecycleRow {
    id: &'static str,
    terminal: LifecycleTerminal,
    units: usize,
    reserved: Observed,
    steps: Vec<LifecycleStep>,
}

impl LifecycleRow {
    /// Index of the step that actually released occupancy, identified by the
    /// release counter moving to one.
    fn terminal_index(&self) -> usize {
        self.steps
            .iter()
            .position(|step| step.observed.release_count == 1)
            .unwrap_or_else(|| panic!("{}: no lifecycle step released occupancy", self.id))
    }

    fn final_observed(&self) -> Observed {
        self.steps
            .last()
            .unwrap_or_else(|| panic!("{}: lifecycle script must not be empty", self.id))
            .observed
    }

    fn successful_commits(&self) -> usize {
        self.steps
            .iter()
            .filter(|step| step.event == LifecycleEvent::Commit && step.result.is_ok())
            .count()
    }
}

fn run_lifecycle_case(case: &LifecycleCase) -> LifecycleRow {
    let accepted = documented_limits();
    let controller = AdmissionController::with_capacities(
        accepted.snapshot(),
        GLOBAL_CAPACITY,
        PARTITION_CAPACITY,
    )
    .expect("the public controller must admit the configured capacities");
    let subject = partition_for(PartitionKind::Verified);

    let mut reservation = if case.expired_deadline {
        // A deadline at "now" is already reached by the time commit runs, which
        // is exactly the deadline disposition this subcase must observe.
        let deadline = Instant::now();
        controller
            .reserve_with_deadline(subject.clone(), case.units, deadline)
            .expect("a deadline-bearing reserve must be admitted")
    } else {
        controller
            .reserve(subject.clone(), case.units)
            .expect("reserve must be admitted")
    };

    let reserved = observe(&controller, &subject);
    assert_eq!(
        reserved.global_in_use, case.units,
        "{}: reserve must charge the global counter",
        case.id
    );
    assert_eq!(
        reserved.partition_in_use, case.units,
        "{}: reserve must charge the partition counter",
        case.id
    );

    let mut steps = Vec::new();
    for (event, expected) in case.script {
        let result = match event {
            LifecycleEvent::Commit => reservation.commit(),
            LifecycleEvent::Release => reservation.release(),
            LifecycleEvent::Cancel => reservation.cancel(),
        };
        assert_eq!(
            result, *expected,
            "{}: public result mismatch on {event:?}",
            case.id
        );
        steps.push(LifecycleStep {
            event: *event,
            result,
            observed: observe(&controller, &subject),
        });
    }

    drop(reservation);

    LifecycleRow {
        id: case.id,
        terminal: case.terminal,
        units: case.units,
        reserved,
        steps,
    }
}

fn run_lifecycle_rows() -> Vec<LifecycleRow> {
    LIFECYCLE_CASES.iter().map(run_lifecycle_case).collect()
}

#[test]
fn limit_01_integration_lifecycle_join() {
    let rows = run_lifecycle_rows();

    // Numeric floor: five ordered rows, observable as five rows.
    assert_eq!(
        rows.len(),
        LIFECYCLE_CASES.len(),
        "every declared AC-LIMIT-I-02 subcase must execute"
    );
    assert_eq!(
        rows.len(),
        5,
        "AC-LIMIT-I-02 numeric floor is 5 ordered rows"
    );
    let ids: Vec<&str> = rows.iter().map(|row| row.id).collect();
    assert_eq!(
        ids,
        vec![
            "LIMIT-I-02.01",
            "LIMIT-I-02.02",
            "LIMIT-I-02.03",
            "LIMIT-I-02.04",
            "LIMIT-I-02.05",
        ],
        "AC-LIMIT-I-02 subcases must run in the frozen order"
    );
    let terminals: Vec<LifecycleTerminal> = rows.iter().map(|row| row.terminal).collect();
    assert_eq!(
        terminals,
        vec![
            LifecycleTerminal::Success,
            LifecycleTerminal::Cancellation,
            LifecycleTerminal::Deadline,
            LifecycleTerminal::CommitFailure,
            LifecycleTerminal::RepeatedTerminal,
        ],
        "the five rows must cover success, cancellation, deadline, commit failure and repeated terminal"
    );

    for row in &rows {
        assert_eq!(
            row.reserved.generation, PROTOCOL_LIMITS_INITIAL_GENERATION,
            "{}: the accepted snapshot generation must never move",
            row.id
        );

        // Success commits exactly once; no other disposition commits at all.
        let expected_commits = usize::from(matches!(
            row.terminal,
            LifecycleTerminal::Success | LifecycleTerminal::RepeatedTerminal
        ));
        assert_eq!(
            row.successful_commits(),
            expected_commits,
            "{}: successful commit count mismatch",
            row.id
        );

        // Exactly one step releases occupancy, and it is the only one.
        let terminal_index = row.terminal_index();
        let terminal_observed = row.steps[terminal_index].observed;
        assert_eq!(
            terminal_observed.release_count, 1,
            "{}: the terminal path must release exactly once",
            row.id
        );
        assert_eq!(
            terminal_observed.global_in_use, 0,
            "{}: the terminal path must return the global counter to zero",
            row.id
        );
        assert_eq!(
            terminal_observed.partition_in_use, 0,
            "{}: the terminal path must return the partition counter to zero",
            row.id
        );
        assert_eq!(
            terminal_observed.committed_work, 0,
            "{}: settlement must discharge committed work",
            row.id
        );
        assert_eq!(
            terminal_observed.live_reservations, 0,
            "{}: the settled reservation must not stay live",
            row.id
        );

        // Steps before the terminal hold the reserved occupancy and never release.
        for (index, step) in row.steps.iter().take(terminal_index).enumerate() {
            assert_eq!(
                step.observed.release_count, 0,
                "{}: step {index} ({:?}) must not release",
                row.id, step.event
            );
            assert_eq!(
                step.observed.global_in_use, row.units,
                "{}: step {index} ({:?}) must hold the reserved global occupancy",
                row.id, step.event
            );
            assert_eq!(
                step.observed.partition_in_use, row.units,
                "{}: step {index} ({:?}) must hold the reserved partition occupancy",
                row.id, step.event
            );
        }

        // No later lifecycle event reopens or recharges the reservation: every
        // observation after the terminal is byte-for-byte identical to it.
        for (index, step) in row.steps.iter().enumerate().skip(terminal_index + 1) {
            assert_eq!(
                step.result,
                Err(AdmissionError::AlreadySettled),
                "{}: step {index} ({:?}) after settlement must refuse",
                row.id,
                step.event
            );
            assert_eq!(
                step.observed, terminal_observed,
                "{}: step {index} ({:?}) after settlement must not reopen or recharge",
                row.id, step.event
            );
        }

        // Dropping the settled reservation must not release a second time.
        assert_eq!(
            row.final_observed(),
            terminal_observed,
            "{}: the final observation must equal the terminal observation",
            row.id
        );
    }

    // The repeated-terminal row must actually repeat: four post-terminal events.
    let repeated = rows
        .iter()
        .find(|row| row.terminal == LifecycleTerminal::RepeatedTerminal)
        .expect("the repeated-terminal row must be present");
    assert_eq!(
        repeated.steps.len() - repeated.terminal_index() - 1,
        4,
        "LIMIT-I-02.05 must apply four terminal events after settlement"
    );
}

// ---------------------------------------------------------------------------
// Bridge quartet — frozen positive and its one-variable planted negative
// ---------------------------------------------------------------------------

/// The number of upstream LIMIT-A / LIMIT-B evidence rows this leaf emits ahead
/// of its own LIMIT-I content, in the order `AC-LIMIT-V-01` enumerates them.
const UPSTREAM_EVIDENCE_ROWS: usize = 6;

/// The six upstream LIMIT-A / LIMIT-B acceptance evidence groups, bound into
/// this leaf's receipt by name.
///
/// `AC-LIMIT-V-01` requires the verification leaf to find ordered evidence IDs
/// `LIMIT-A-01`..`LIMIT-A-03` and `LIMIT-B-01`..`LIMIT-B-03` in this receipt
/// alongside this leaf's own `LIMIT-I-01`..`LIMIT-I-02` — eight groups against
/// its declared floor of eight. Before this binding existed the receipt carried
/// only its own two, so a change to an upstream row could not move the
/// integration digest and the join certified "whatever A and B happen to be
/// now".
///
/// EVERY FIELD BELOW IS DERIVED, never a literal. Each row folds over the source
/// collection this leaf already re-derives, so deleting or substituting a source
/// row changes that row's text and therefore the digest. A hand-written row set
/// would be a count that survives the deletion of what it counts, which is the
/// defect this binding exists to prevent rather than to re-create.
fn upstream_evidence_rows(
    accepted: &ProtocolLimits,
    public_rows: &[PublicJoinRow],
    lifecycle_rows: &[LifecycleRow],
) -> Vec<String> {
    // LIMIT-A-01 — the configured catalog, folded per row so a removed bound
    // changes both the count and the text.
    let bounds: Vec<String> = configured_bound_rows()
        .into_iter()
        .map(|(limit, units)| {
            let ceiling =
                ProtocolLimits::hard_ceiling(limit).expect("a countable catalog row has a ceiling");
            format!("{limit}={units}/{ceiling}")
        })
        .collect();

    // LIMIT-A-02 — the three shipped domains, each re-probed through its public
    // constructor rather than named. A domain that stopped being distinct moves
    // its own field.
    let domains: Vec<String> = [
        PartitionKind::PreAuth,
        PartitionKind::Verified,
        PartitionKind::AuthorizationFlow,
    ]
    .into_iter()
    .map(|kind| {
        let partition = partition_for(kind);
        format!(
            "{kind:?}=pre_auth:{},verified:{}",
            partition.is_pre_auth(),
            partition.is_verified()
        )
    })
    .collect();

    // LIMIT-A-03 — checked arithmetic at N-1 / N / N+1 over the same catalog, so
    // this row is sensitive to the bound rows as well as to the arithmetic.
    let arithmetic: Vec<String> = configured_bound_rows()
        .into_iter()
        .map(|(limit, units)| {
            let below = accepted.try_charge(limit, 0, units - 1).is_ok();
            let at = accepted.try_charge(limit, 0, units).is_ok();
            let above = accepted.try_charge(limit, 0, units + 1).is_err();
            format!("{limit}={below}/{at}/{above}")
        })
        .collect();

    // LIMIT-B-01 — the executed reserve outcomes.
    let reserve: Vec<String> = public_rows
        .iter()
        .map(|row| {
            let outcome = if row.result.is_ok() {
                "admitted"
            } else {
                "refused"
            };
            format!("{}={}:{outcome}", row.id, row.requested)
        })
        .collect();

    // LIMIT-B-02 — the terminal disposition and discharge counters per row.
    let lifecycle: Vec<String> = lifecycle_rows
        .iter()
        .map(|row| {
            let observed = row.final_observed();
            format!(
                "{}={:?}:released:{}:committed:{}",
                row.id, row.terminal, observed.release_count, observed.committed_work
            )
        })
        .collect();

    // LIMIT-B-03 — cross-partition isolation as this leaf actually exercises it:
    // the prefill charges peer partitions, so a subject whose own partition
    // counter stays zero while global is occupied is the fairness property.
    let fairness: Vec<String> = public_rows
        .iter()
        .map(|row| {
            format!(
                "{}=peer_global:{}:subject_partition:{}",
                row.id, row.before.global_in_use, row.before.partition_in_use
            )
        })
        .collect();

    vec![
        format!(
            "LIMIT-A-01 LIMIT01-A-BOUNDS-v1 rows={} generation={} {}",
            bounds.len(),
            accepted.generation(),
            bounds.join(" ")
        ),
        format!(
            "LIMIT-A-02 LIMIT01-A-PARTITIONS-v1 rows={} {}",
            domains.len(),
            domains.join(" ")
        ),
        format!(
            "LIMIT-A-03 LIMIT01-A-ARITHMETIC-v1 rows={} {}",
            arithmetic.len(),
            arithmetic.join(" ")
        ),
        format!(
            "LIMIT-B-01 LIMIT01-B-RESERVE-v1 rows={} global={GLOBAL_CAPACITY} partition={PARTITION_CAPACITY} {}",
            reserve.len(),
            reserve.join(" ")
        ),
        format!(
            "LIMIT-B-02 LIMIT01-B-LIFECYCLE-v1 rows={} {}",
            lifecycle.len(),
            lifecycle.join(" ")
        ),
        format!(
            "LIMIT-B-03 LIMIT01-B-FAIRNESS-v1 rows={} {}",
            fairness.len(),
            fairness.join(" ")
        ),
    ]
}

/// The ordered joined receipt over the LIMIT-A bound rows, the LIMIT-B public
/// join rows, and the LIMIT-B lifecycle rows.
fn joined_receipt(
    accepted: &ProtocolLimits,
    public_rows: &[PublicJoinRow],
    lifecycle_rows: &[LifecycleRow],
) -> Vec<String> {
    let mut receipt = upstream_evidence_rows(accepted, public_rows, lifecycle_rows);
    receipt.push(format!(
        "LIMIT01-I-PUBLIC-JOIN-v1 generation={}",
        accepted.generation()
    ));
    for (limit, units) in configured_bound_rows() {
        let ceiling =
            ProtocolLimits::hard_ceiling(limit).expect("a countable catalog row has a ceiling");
        receipt.push(format!(
            "LIMIT-A {limit} configured={units} ceiling={ceiling}"
        ));
    }
    for row in public_rows {
        receipt.push(format!(
            "{} requested={} result={:?} global={} partition={} committed={} released={}",
            row.id,
            row.requested,
            row.result,
            row.after_attempt.global_in_use,
            row.after_attempt.partition_in_use,
            row.after_commit
                .map_or(0, |observed| observed.committed_work),
            row.after_release
                .map_or(0, |observed| observed.release_count),
        ));
    }
    receipt.push("LIMIT01-I-LIFECYCLE-JOIN-v1".to_owned());
    for row in lifecycle_rows {
        let observed = row.final_observed();
        receipt.push(format!(
            "{} terminal={:?} units={} global={} partition={} committed={} released={}",
            row.id,
            row.terminal,
            row.units,
            observed.global_in_use,
            observed.partition_in_use,
            observed.committed_work,
            observed.release_count,
        ));
    }
    receipt
}

#[test]
fn limit_01_i_positive() {
    // The shipped public entrypoints, bound at their exact published
    // signatures and then actually called through those bindings. A signature
    // change or a loss of the facade re-export fails this compilation.
    let reserve: fn(
        &AdmissionController,
        AdmissionPartition,
        usize,
    ) -> Result<AdmissionReservation, AdmissionError> = AdmissionController::reserve;
    let commit: fn(&mut AdmissionReservation) -> Result<(), AdmissionError> =
        AdmissionReservation::commit;
    let release: fn(&mut AdmissionReservation) -> Result<(), AdmissionError> =
        AdmissionReservation::release;

    // LIMIT-A output: the accepted bounds catalog, through the publicly named
    // builder type.
    let builder: ProtocolLimitsBuilder = ProtocolLimits::builder();
    let accepted = builder
        .json_rpc_max_body_bytes(DEFAULT_JSON_RPC_MAX_BODY_BYTES)
        .metadata_max_entries(DEFAULT_METADATA_MAX_ENTRIES)
        .metadata_max_bytes(DEFAULT_METADATA_MAX_BYTES)
        .uri_max_bytes(DEFAULT_URI_MAX_BYTES)
        .cancellation_reason_max_bytes(DEFAULT_CANCELLATION_REASON_MAX_BYTES)
        .cursor_max_bytes(DEFAULT_CURSOR_MAX_BYTES)
        .build()
        .expect("the publicly named builder must admit the documented default bounds");
    assert_eq!(
        accepted,
        documented_limits(),
        "the publicly named builder must produce the same accepted snapshot"
    );
    assert_eq!(accepted.generation(), PROTOCOL_LIMITS_INITIAL_GENERATION);
    assert_eq!(accepted.validate(), Ok(()));

    for (limit, units) in configured_bound_rows() {
        assert_eq!(
            accepted.configured_units(limit),
            Ok(units),
            "accepted catalog row {limit} must report its configured units"
        );
        let ceiling =
            ProtocolLimits::hard_ceiling(limit).expect("a countable catalog row has a ceiling");
        assert!(
            units <= ceiling,
            "accepted catalog row {limit} must stay inside its hard ceiling"
        );
        // N-1 and N charge; N+1 refuses on the same row.
        assert_eq!(accepted.try_charge(limit, 0, units - 1), Ok(units - 1));
        assert_eq!(accepted.try_charge(limit, 0, units), Ok(units));
        assert_eq!(
            accepted.try_charge(limit, 0, units + 1),
            Err(ProtocolLimitsError::ChargeExceedsLimit {
                limit,
                requested: units + 1,
                ceiling: units,
            })
        );
    }
    assert_eq!(
        accepted.configured_units(ProtocolLimit::LogicalExchangeWallClock),
        Err(ProtocolLimitsError::NotCountable {
            limit: ProtocolLimit::LogicalExchangeWallClock,
        }),
        "the duration row must refuse a usize projection"
    );

    // LIMIT-A output: the three public partition domains are distinct and
    // correctly classified.
    let pre_auth = partition_for(PartitionKind::PreAuth);
    let verified = partition_for(PartitionKind::Verified);
    let flow = partition_for(PartitionKind::AuthorizationFlow);
    assert!(pre_auth.is_pre_auth() && !pre_auth.is_verified());
    assert!(verified.is_verified() && !verified.is_pre_auth());
    assert!(!flow.is_verified() && !flow.is_pre_auth());
    assert_ne!(pre_auth, verified);
    assert_ne!(verified, flow);
    assert_ne!(pre_auth, flow);

    // The join: LIMIT-B consumes exactly the accepted LIMIT-A snapshot and
    // carries it unchanged across the whole reserve/commit/release cycle.
    let controller = AdmissionController::with_capacities(
        accepted.snapshot(),
        GLOBAL_CAPACITY,
        PARTITION_CAPACITY,
    )
    .expect("the public controller must admit the configured capacities");
    assert_eq!(
        controller.limits(),
        &accepted,
        "the controller must carry the accepted LIMIT-A snapshot unchanged"
    );

    let mut reservation = reserve(&controller, verified.clone(), PARTITION_CAPACITY)
        .expect("reserve of N units must be admitted");
    assert_eq!(controller.limits(), &accepted);
    assert_eq!(controller.global_in_use(), PARTITION_CAPACITY);
    assert_eq!(controller.partition_in_use(&verified), PARTITION_CAPACITY);

    commit(&mut reservation).expect("commit must succeed");
    assert_eq!(controller.limits(), &accepted);
    assert_eq!(controller.committed_work(), PARTITION_CAPACITY);
    assert_eq!(controller.global_in_use(), PARTITION_CAPACITY);

    release(&mut reservation).expect("release must succeed");
    assert_eq!(
        controller.limits(),
        &accepted,
        "the accepted snapshot must survive the full lifecycle unchanged"
    );
    assert_eq!(controller.global_in_use(), 0);
    assert_eq!(controller.partition_in_use(&verified), 0);
    assert_eq!(controller.committed_work(), 0);
    assert_eq!(controller.release_count(), 1);
    assert_eq!(controller.live_reservation_count(), 0);

    // The joined ordered receipt over both acceptance rows.
    let public_rows = run_public_join_rows();
    let lifecycle_rows = run_lifecycle_rows();
    assert_eq!(
        public_rows.len(),
        6,
        "AC-LIMIT-I-01 numeric floor is 6 rows"
    );
    assert_eq!(
        lifecycle_rows.len(),
        5,
        "AC-LIMIT-I-02 numeric floor is 5 rows"
    );

    let receipt = joined_receipt(&accepted, &public_rows, &lifecycle_rows);
    assert_eq!(
        receipt.len(),
        UPSTREAM_EVIDENCE_ROWS + 1 + 6 + 6 + 1 + 5,
        "the joined receipt must carry the six upstream LIMIT-A/LIMIT-B evidence rows, both digest headers, six bound rows, six public-join rows and five lifecycle rows"
    );
    // AC-LIMIT-V-01 requires EIGHT ordered evidence groups in this receipt:
    // LIMIT-A-01..03, LIMIT-B-01..03, then this leaf's own LIMIT-I-01..02.
    // Six of the eight were absent before this binding existed, which also made
    // that criterion's one-variable negative vacuous: with six already missing,
    // removing a seventh and observing a rejection proved nothing.
    for (index, (group, digest)) in [
        ("LIMIT-A-01", "LIMIT01-A-BOUNDS-v1"),
        ("LIMIT-A-02", "LIMIT01-A-PARTITIONS-v1"),
        ("LIMIT-A-03", "LIMIT01-A-ARITHMETIC-v1"),
        ("LIMIT-B-01", "LIMIT01-B-RESERVE-v1"),
        ("LIMIT-B-02", "LIMIT01-B-LIFECYCLE-v1"),
        ("LIMIT-B-03", "LIMIT01-B-FAIRNESS-v1"),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            receipt[index].starts_with(&format!("{group} {digest} rows=")),
            "upstream evidence row {index} must be {group} carrying {digest}, got {:?}",
            receipt[index]
        );
        // A group that folded over an empty collection would satisfy the prefix
        // above while binding nothing, so require a non-zero row count too.
        assert!(
            !receipt[index].contains("rows=0 "),
            "{group}: an empty source collection binds nothing"
        );
    }
    // DISCONFIRMER: a binding that cannot move is decorative, and the counts
    // above would not notice. Prove each half is sensitive to its own source.
    //
    // B side, by PERTURBATION: drop one row from each source collection and
    // require the corresponding evidence row to change.
    assert!(!public_rows.is_empty() && !lifecycle_rows.is_empty());
    let short_public = &public_rows[..public_rows.len() - 1];
    let short_lifecycle = &lifecycle_rows[..lifecycle_rows.len() - 1];
    let perturbed = upstream_evidence_rows(&accepted, short_public, short_lifecycle);
    for index in [3usize, 4, 5] {
        assert_ne!(
            perturbed[index], receipt[index],
            "evidence row {index} did not move when a source row was removed, so it \
             binds nothing"
        );
    }
    // A side, by CONTENT: these fold over `configured_bound_rows()`, a fixed
    // array with no runtime shorter form, so instead require every element to be
    // named. A removed bound necessarily changes both the count and the text.
    for (limit, _) in configured_bound_rows() {
        let named = format!("{limit}=");
        assert!(
            receipt[0].contains(&named),
            "LIMIT-A-01 must name every configured bound; {limit} is absent"
        );
        assert!(
            receipt[2].contains(&named),
            "LIMIT-A-03 must exercise arithmetic on every configured bound; {limit} is absent"
        );
    }
    // LIMIT-A-02 folds over the three shipped domains, which are likewise fixed
    // at compile time, so it gets the same content treatment: a dropped domain
    // removes its name from the row.
    for kind in [
        PartitionKind::PreAuth,
        PartitionKind::Verified,
        PartitionKind::AuthorizationFlow,
    ] {
        assert!(
            receipt[1].contains(&format!("{kind:?}=")),
            "LIMIT-A-02 must name every shipped admission domain; {kind:?} is absent"
        );
    }

    assert!(receipt[UPSTREAM_EVIDENCE_ROWS].starts_with("LIMIT01-I-PUBLIC-JOIN-v1 generation=1"));
    assert_eq!(
        receipt[UPSTREAM_EVIDENCE_ROWS + 13],
        "LIMIT01-I-LIFECYCLE-JOIN-v1"
    );
    for (index, id) in [
        "LIMIT-I-01.01",
        "LIMIT-I-01.02",
        "LIMIT-I-01.03",
        "LIMIT-I-01.04",
        "LIMIT-I-01.05",
        "LIMIT-I-01.06",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            receipt[UPSTREAM_EVIDENCE_ROWS + 7 + index].starts_with(id),
            "receipt row {} must be {id}",
            UPSTREAM_EVIDENCE_ROWS + 7 + index
        );
    }
    for (index, id) in [
        "LIMIT-I-02.01",
        "LIMIT-I-02.02",
        "LIMIT-I-02.03",
        "LIMIT-I-02.04",
        "LIMIT-I-02.05",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            receipt[UPSTREAM_EVIDENCE_ROWS + 14 + index].starts_with(id),
            "receipt row {} must be {id}",
            UPSTREAM_EVIDENCE_ROWS + 14 + index
        );
    }
    // Every lifecycle row lands on the same fully-discharged terminal tuple.
    for index in (UPSTREAM_EVIDENCE_ROWS + 14)..(UPSTREAM_EVIDENCE_ROWS + 19) {
        assert!(
            receipt[index].ends_with("global=0 partition=0 committed=0 released=1"),
            "lifecycle receipt row {index} must show exact-once release and zero retained occupancy"
        );
    }
}

#[test]
fn limit_01_i_planted_negative() {
    // Each mutation below runs the byte-identical positive setup in a fresh
    // controller and changes exactly one variable.
    let accepted = documented_limits();
    let verified = partition_for(PartitionKind::Verified);

    // --- Mutation 1: only the requested units move from N to N + 1. ---------
    let control = AdmissionController::with_capacities(
        accepted.snapshot(),
        GLOBAL_CAPACITY,
        PARTITION_CAPACITY,
    )
    .expect("the public controller must admit the configured capacities");
    let mut admitted = control
        .reserve(verified.clone(), PARTITION_CAPACITY)
        .expect("the unmutated reserve of N units must be admitted");
    assert_eq!(control.global_in_use(), PARTITION_CAPACITY);
    assert_eq!(control.partition_in_use(&verified), PARTITION_CAPACITY);
    admitted.release().expect("the control path releases once");
    assert_eq!(
        full_state(&control),
        FullState {
            generation: PROTOCOL_LIMITS_INITIAL_GENERATION,
            global_in_use: 0,
            pre_auth_in_use: 0,
            verified_in_use: 0,
            authorization_flow_in_use: 0,
            committed_work: 0,
            release_count: 1,
            admission_count: 1,
            live_reservations: 0,
        },
        "the unmutated control path admits N units and releases exactly once"
    );

    let mutated = AdmissionController::with_capacities(
        accepted.snapshot(),
        GLOBAL_CAPACITY,
        PARTITION_CAPACITY,
    )
    .expect("the public controller must admit the configured capacities");
    let before = full_state(&mutated);
    let refusal = mutated
        .reserve(verified.clone(), PARTITION_CAPACITY + 1)
        .expect_err("reserving N + 1 units must reach the typed refusal boundary");
    assert_eq!(
        refusal,
        AdmissionError::PartitionCapacityExceeded {
            requested: PARTITION_CAPACITY + 1,
            in_use: 0,
            limit: PARTITION_CAPACITY,
        },
        "the one-variable unit mutation must produce the stable typed refusal"
    );
    let after = full_state(&mutated);
    assert_eq!(
        after, before,
        "a refused reserve must leave every admission state field byte-for-byte unchanged"
    );
    // The same proof stated field by field over every named mutable field.
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.global_in_use, before.global_in_use);
    assert_eq!(after.pre_auth_in_use, before.pre_auth_in_use);
    assert_eq!(after.verified_in_use, before.verified_in_use);
    assert_eq!(
        after.authorization_flow_in_use,
        before.authorization_flow_in_use
    );
    assert_eq!(after.committed_work, before.committed_work);
    assert_eq!(after.release_count, before.release_count);
    assert_eq!(after.admission_count, before.admission_count);
    assert_eq!(after.live_reservations, before.live_reservations);
    assert_eq!(
        before,
        FullState {
            generation: PROTOCOL_LIMITS_INITIAL_GENERATION,
            global_in_use: 0,
            pre_auth_in_use: 0,
            verified_in_use: 0,
            authorization_flow_in_use: 0,
            committed_work: 0,
            release_count: 0,
            admission_count: 0,
            live_reservations: 0,
        },
        "the pristine controller state must be the documented zero state"
    );
    // The refusal is not a poisoned controller: the unmutated request still
    // succeeds on the same instance.
    let mut recovered = mutated
        .reserve(verified.clone(), PARTITION_CAPACITY)
        .expect("the unmutated reserve must still be admitted after the refusal");
    recovered
        .release()
        .expect("recovered reservation releases once");
    assert_eq!(mutated.global_in_use(), 0);
    assert_eq!(mutated.release_count(), 1);

    // --- Mutation 2: only a duplicate terminal event is added. --------------
    let lifecycle = AdmissionController::with_capacities(
        accepted.snapshot(),
        GLOBAL_CAPACITY,
        PARTITION_CAPACITY,
    )
    .expect("the public controller must admit the configured capacities");
    let mut reservation = lifecycle
        .reserve(verified.clone(), 2)
        .expect("reserve must be admitted");
    reservation.commit().expect("commit must succeed");
    reservation
        .release()
        .expect("the fixed terminal disposition is release");
    let settled = full_state(&lifecycle);
    assert_eq!(
        settled.release_count, 1,
        "the terminal path released exactly once"
    );
    assert_eq!(settled.global_in_use, 0);
    assert_eq!(settled.committed_work, 0);

    // Each duplicate terminal event is applied and checked on its own, so the
    // unchanged-state proof is bound to that single added event.
    assert_eq!(
        reservation.release(),
        Err(AdmissionError::AlreadySettled),
        "a duplicate release must follow the fixed terminal disposition"
    );
    assert_eq!(
        full_state(&lifecycle),
        settled,
        "a duplicate release must leave every state field byte-for-byte unchanged"
    );
    assert_eq!(
        reservation.commit(),
        Err(AdmissionError::AlreadySettled),
        "a commit after settlement must follow the fixed terminal disposition"
    );
    assert_eq!(
        full_state(&lifecycle),
        settled,
        "a commit after settlement must leave every state field byte-for-byte unchanged"
    );
    assert_eq!(
        reservation.cancel(),
        Err(AdmissionError::AlreadySettled),
        "a cancel after settlement must follow the fixed terminal disposition"
    );
    assert_eq!(
        full_state(&lifecycle),
        settled,
        "a cancel after settlement must leave every state field byte-for-byte unchanged"
    );
    drop(reservation);
    assert_eq!(
        full_state(&lifecycle),
        settled,
        "dropping a settled reservation must not release a second time"
    );

    // --- Mutation 3: only one bound row is raised past its hard ceiling. ----
    let over_ceiling = ProtocolLimits::builder()
        .json_rpc_max_body_bytes(DEFAULT_JSON_RPC_MAX_BODY_BYTES)
        .metadata_max_entries(HARD_METADATA_MAX_ENTRIES + 1)
        .metadata_max_bytes(DEFAULT_METADATA_MAX_BYTES)
        .uri_max_bytes(DEFAULT_URI_MAX_BYTES)
        .cancellation_reason_max_bytes(DEFAULT_CANCELLATION_REASON_MAX_BYTES)
        .cursor_max_bytes(DEFAULT_CURSOR_MAX_BYTES)
        .build()
        .expect_err("a row above its hard ceiling must be refused");
    assert_eq!(
        over_ceiling,
        ProtocolLimitsError::ExceedsHardCeiling {
            limit: ProtocolLimit::MetadataEntries,
        },
        "the one-variable bound mutation must produce the stable typed refusal"
    );
    assert_eq!(
        accepted,
        documented_limits(),
        "the refused builder must not disturb the accepted snapshot"
    );
    assert_eq!(accepted.validate(), Ok(()));
    assert_eq!(
        accepted.configured_units(ProtocolLimit::MetadataEntries),
        Ok(usize::from(DEFAULT_METADATA_MAX_ENTRIES)),
        "the accepted metadata-entry row must remain at its configured value"
    );

    // --- Mutation 4: only the partition-key provenance changes. -------------
    let provenance = AdmissionController::with_capacities(
        accepted.snapshot(),
        GLOBAL_CAPACITY,
        PARTITION_CAPACITY,
    )
    .expect("the public controller must admit the configured capacities");
    let pristine = full_state(&provenance);
    assert_eq!(
        QuotaPartitionKey::try_from_request_identifier("untrusted-caller-req-id"),
        Err(SealedAdmissionKeyError::RequestSuppliedIdentifier),
        "a request-supplied identifier must not mint a verified quota partition key"
    );
    assert_eq!(
        AdmissionPartition::try_from_request_identifier("untrusted-caller-req-id"),
        Err(SealedAdmissionKeyError::RequestSuppliedIdentifier),
        "a request-supplied identifier must not mint a verified admission partition"
    );
    assert_eq!(
        PreAuthSourceBucketKey::from_listener_and_source("", "tcp:203.0.113.8"),
        Err(SealedAdmissionKeyError::EmptyField),
        "an empty listener domain must be refused"
    );
    assert_eq!(
        full_state(&provenance),
        pristine,
        "a refused key mint must leave every admission state field byte-for-byte unchanged"
    );

    // --- Mutation 5: only the requested unit count drops to zero. -----------
    let zero = provenance
        .reserve(verified.clone(), 0)
        .expect_err("a zero-unit reserve must be refused");
    assert_eq!(zero, AdmissionError::ZeroUnits);
    assert_eq!(
        full_state(&provenance),
        pristine,
        "a refused zero-unit reserve must leave every admission state field unchanged"
    );
}
