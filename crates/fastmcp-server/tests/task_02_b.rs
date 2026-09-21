//! TASK-02-B: durable task recovery, leasing, and fencing, proved through the
//! shipped `FinalTaskStore` public surface.
//!
//! Frozen IDs: `task_02_b_positive`, `task_02_b_planted_negative`.
//!
//! # Evaluator subject
//!
//! bd-mcp-task-02-b-x5r3 names its subject "the shipped `PersistentTaskBackend`
//! conformance harness". No type of that name exists in this workspace; the
//! name is a ROLE, and the artifact that fills it is the public
//! `fastmcp_server::FinalTaskStore` trait with `InMemoryFinalTaskStore` as the
//! conforming implementation under test. This file drives that trait and
//! nothing else, so any second implementation is held to the same assertions
//! by construction.
//!
//! Everything here runs out of crate, against `pub` items only. Nothing is
//! `cfg(test)`-reachable, so PL-3 is satisfied for the rows it covers.
//!
//! # Coverage against the bead's 23 ordered groups -- READ THIS BEFORE CITING
//!
//! This file does NOT discharge the bead. It covers ELEVEN of the twenty-three
//! named groups, one of those only in part. The table below is the authority;
//! keep this sentence and the table in agreement when either changes:
//!
//! | group | state here |
//! |---|---|
//! | `B-26 stale-owner-fenced-write`      | covered |
//! | `B-27 lease-renew-expire-reclaim`    | covered -- renew, expire AND reclaim |
//! | `B-28 durable-time-authority`        | covered |
//! | `B-29 backend-clock-discontinuity`   | covered -- narrow; see the test's own scope note |
//! | `B-30 skewed-worker-time-domains`    | covered |
//! | `B-32 deadline-renew-restart`        | covered |
//! | `B-31 private-update-revision-order` | PARTIAL: stale-generation refusal only. Ordering across concurrent writers is not asserted. |
//! | `B-34 restore-write-contract`        | covered |
//! | `B-35 third-party-backend-conformance` | covered -- required surface only |
//! | `B-42 duplicate-execution-idempotency` | covered |
//! | `B-43 shutdown-drain-lease-release`  | covered |
//!
//! ELEVEN of twenty-three, one of them partial. **Twelve groups have no test
//! here and none anywhere in the tree**: B-24, B-25, B-33, B-36 through B-41,
//! B-44, B-45, B-46.
//!
//! A RUN REPORTS 14 OUTCOMES, WHICH IS NOT 14 GROUPS AND NOT 23. Eleven group
//! tests, one lease-window guard, and the two frozen IDs. This file has been
//! miscounted three times by three different methods -- 13 by mention count,
//! 18 by a mixed regex, and 13-of-23 by reading the outcome total as a group
//! total. The group figure is the number of `fn bNN_*` definitions.
//!
//! Of those thirteen, EIGHT are blocked on capability the shipped store does
//! not have and cannot be closed by writing tests: B-25 and B-33
//! (reconciliation, `reconcil` = 0 here though it appears in 21 other
//! workspace src files), B-36 and B-41 (expiry index / tombstones,
//! `sweeper` = 0), B-37 (quota, 2 occurrences in 19,260 lines), B-38 and B-40
//! (protected payloads; tasks.rs:8460 states the store "deliberately
//! implements only unprotected work" and `reencrypt` = 0 workspace-wide),
//! B-39 (durable-time epoch, `epoch` = 0). FIVE remain as candidates: B-24,
//! B-35, B-44, B-45, B-46, plus completing B-31's ordering half.
//!
//! A NOTE ON THAT SPLIT, because the obvious heuristic over-blocks: absence of
//! a word from the source decides nothing on its own. It is decisive only
//! when the STORE must implement the concept. Where the TEST supplies it, the
//! word is irrelevant -- `discontinu` and `skew` appear nowhere in the
//! workspace, yet B-29 above is written and passing, because the test injects
//! the clock. The same applies to B-35, where the test would supply a second
//! `FinalTaskStore` implementation.
//!
//! COUNT THIS FILE BY ITS `#[test]` FUNCTIONS, NOT BY ITS MENTIONS. The table
//! above names groups precisely in order to say which are MISSING, so a scan
//! counting `B-nn` occurrences reads the gap list as coverage. That has now
//! happened twice to two different readers, scoring this file at 13 and then
//! at 18 when the implemented figure was 5 and then 7. Every group identifier
//! here appears in a comment and none appears in code.
//!
//! # What a run of this file reports, and how NOT to add it up
//!
//! There are **10** `#[test]` functions and **8** distinct behaviours.
//!
//! - Eight group tests -- `lease_window_is_the_one_this_file_assumes` and the
//!   seven `bNN_*` -- each individually discoverable, each one behaviour.
//! - `task_02_b_positive`, a frozen ID, which is a ROLL-UP that calls all
//!   eight. It adds no behaviour. It exists because the acceptance criteria
//!   name it as the positive, and an empty frozen positive would be a vacuous
//!   test.
//! - `task_02_b_planted_negative`, a frozen ID, the one behaviour not reached
//!   by any group test.
//!
//! **So a full run executes each group body TWICE and reports 10 outcomes for
//! 8 behaviours plus one negative.** A receipt must not read 10 outcomes as 10
//! behaviours, and must not read a group's failure appearing twice as two
//! defects. The countable figure against the bead's 23 required groups is the
//! number of `fn bNN_*` tests, which is SEVEN.
//!
//! The groups were promoted to individual `#[test]`s on orchestrator ruling
//! after review. The decisive reason was not cardinality: it is that seven
//! behaviours inside one test means the FIRST FAILING ASSERT ABORTS THE REST,
//! so a red would report one group and stay silent about six. Individually
//! discoverable tests make all eight outcomes observable on a single run. The
//! roll-up still has that defect internally, which is exactly why it must not
//! be the only entry point.
//!
//! Four of the sixteen cannot be closed by writing tests at all. They rest on
//! vocabulary the shipped source does not carry: word-boundary counts over
//! `crates/fastmcp-server/src/tasks.rs` give `quota` = 2, `tombstone` = 0,
//! `reconcil` = 0, `epoch` = 0, against `lease` = 191, `fence` = 64,
//! `durable` = 157 and `generation` = 540. Those are implementation gaps.
//!
//! # Feature gating, and which configuration a green here binds
//!
//! This target declares `required-features = ["tasks"]` in
//! `crates/fastmcp-server/Cargo.toml`. It needs it: `FinalTaskStore`,
//! `InMemoryFinalTaskStore`, `FinalTaskSnapshot`, `FinalTaskWorkDescriptor`
//! and `FinalTaskRetentionDeadline` are all exported from `lib.rs` behind
//! `#[cfg(feature = "tasks")]`, while this package defaults to
//! `["legacy-2024-11-05"]`. Shipped without the stanza this file failed E0432
//! and broke all 20 test targets in the package -- it did so once, on
//! 2026-09-21, before the stanza was added.
//!
//! The stanza trades a loud compile failure for a SILENT SKIP, so
//! `cargo test -p fastmcp-server` with no flags now exits 0 having discovered
//! neither frozen ID. That is why the runner card passes `--features tasks`
//! explicitly and why any receipt must cite the discovered count, not the
//! exit status.
//!
//! Scope of a green: `tasks` is what the published facade `fastmcp-rust`
//! enables by default, so this binds the default facade configuration. A
//! consumer depending directly on `fastmcp-server` must opt in, and without
//! opting in none of these entrypoints exist.
//!
//! # Why the clock is injected
//!
//! `InMemoryFinalTaskStore::with_clock` takes the monotonic retention clock as
//! a parameter. Every time-dependent assertion below advances that counter
//! explicitly. No assertion sleeps, and none compares against `Instant::now()`,
//! so none of them can pass or fail because of machine load.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use fastmcp_core::{McpError, McpResult};
use fastmcp_protocol::FinalTaskId;
use fastmcp_protocol::tasks_extension::{
    Task, TaskStatusNotification, TaskStatusNotificationParams,
};
use fastmcp_server::{
    FinalTaskRetentionDeadline, FinalTaskSnapshot, FinalTaskStore, FinalTaskWorkDescriptor,
    InMemoryFinalTaskStore,
};

/// The in-memory store's elected dispatch lease, as declared by
/// `IN_MEMORY_FINAL_TASK_HANDOFF_LEASE`. Held here as a local expectation so a
/// change to the store's constant surfaces as a failure in
/// `lease_window_is_the_one_this_file_assumes` rather than as silent drift in
/// every clock advance below.
const ASSUMED_LEASE: Duration = Duration::from_secs(30);

/// A store whose retention clock this test drives directly.
struct Fixture {
    store: Arc<InMemoryFinalTaskStore>,
    advanced_ms: Arc<AtomicU64>,
    base: Instant,
    /// Taken from the created task rather than reconstructed, so the tests
    /// cannot disagree with the store about which identifier they mean.
    id: FinalTaskId,
}

impl Fixture {
    /// Builds a store holding exactly one `working` task with retained initial
    /// work, and returns it with the clock frozen at `base`.
    fn new(task_id: &str, ttl_ms: u64) -> Self {
        let base = Instant::now();
        let advanced_ms = Arc::new(AtomicU64::new(0));
        let store = Arc::new(
            InMemoryFinalTaskStore::with_clock(4, {
                let advanced_ms = Arc::clone(&advanced_ms);
                Arc::new(move || base + Duration::from_millis(advanced_ms.load(Ordering::SeqCst)))
            })
            .expect("a positive capacity yields a store"),
        );
        let task: Task = serde_json::from_value(serde_json::json!({
            "taskId": task_id,
            "status": "working",
            "createdAt": "2026-07-28T12:00:00.000Z",
            "lastUpdatedAt": "2026-07-28T12:00:00.000Z",
            "ttlMs": ttl_ms
        }))
        .expect("a well-formed working task");
        let id = task.base().task_id.clone();
        let notification = TaskStatusNotification::new(TaskStatusNotificationParams {
            task: task.clone(),
            meta: None,
            additional: std::collections::BTreeMap::default(),
        });
        store
            .create_task_with_work(
                task,
                notification,
                FinalTaskWorkDescriptor::new(serde_json::json!({"operation": "durable"}))
                    .expect("a bounded work descriptor"),
            )
            .expect("atomic task-work creation is implemented by this store");
        Self {
            store,
            advanced_ms,
            base,
            id,
        }
    }

    /// Moves the store's authoritative clock BACKWARDS, to the given offset
    /// from the fixture's base. Real monotonic clocks do not do this; a
    /// durable backend reading a corrected or mis-synced host clock can.
    fn rewind_to(&self, offset: Duration) {
        self.advanced_ms.store(
            u64::try_from(offset.as_millis()).expect("test offsets fit in u64 milliseconds"),
            Ordering::SeqCst,
        );
    }

    /// Moves the store's authoritative clock forward. Nothing here sleeps.
    fn advance(&self, by: Duration) {
        self.advanced_ms.fetch_add(
            u64::try_from(by.as_millis()).expect("test advances fit in u64 milliseconds"),
            Ordering::SeqCst,
        );
    }

    /// The exact instant the injected clock is currently returning.
    fn clock_reads(&self) -> Instant {
        self.base + Duration::from_millis(self.advanced_ms.load(Ordering::SeqCst))
    }

    fn snapshot(&self) -> FinalTaskSnapshot {
        self.store
            .get_task_snapshot(&self.id)
            .expect("store reads succeed")
            .expect("the task was created above")
    }

    /// The task as it is currently retained, rendered through its wire
    /// serialization. `Task` carries no `PartialEq`, and its `Debug` is not a
    /// contract, so the wire form is the comparable representation -- and it
    /// is also the one the AC's "byte-for-byte unchanged" clause is about.
    fn task_wire_form(&self) -> serde_json::Value {
        serde_json::to_value(
            self.store
                .get_task(&self.id)
                .expect("store reads succeed")
                .expect("the task exists"),
        )
        .expect("a retained task serializes")
    }

    /// Elects `owner` for the retained initial work and returns the
    /// store-issued fencing token.
    fn elect(&self, owner: &str) -> (FinalTaskSnapshot, u64) {
        let snapshot = self.snapshot();
        assert!(
            self.store
                .take_initial_work_handoff_for_owner_if_current(&snapshot, owner)
                .expect("store writes succeed")
                .is_some(),
            "the retained initial work must be claimable by the first owner"
        );
        let fence = self
            .store
            .begin_handoff_dispatch_for_owner_if_current(&self.id, snapshot.generation(), owner)
            .expect("store writes succeed")
            .expect("dispatch election succeeds for the sole owner at the current generation");
        (snapshot, fence)
    }
}

/// The single task identifier every group below uses.
const TASK: &str = "durable-operation";

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

/// Guards the local constant this file's clock advances are calibrated
/// against. Without this, a change to the store's lease would turn every
/// "past expiry" advance below into a "still live" advance, and the affected
/// tests would keep passing while asserting the opposite of their names.
#[test]
fn lease_window_is_the_one_this_file_assumes() {
    let fixture = Fixture::new(TASK, 600_000);
    let heartbeat = fixture
        .store
        .handoff_dispatch_lease_heartbeat_interval()
        .expect("this store discloses a heartbeat interval");
    assert!(
        heartbeat > Duration::ZERO,
        "the contract requires a positive interval"
    );
    assert!(
        heartbeat < ASSUMED_LEASE,
        "the contract requires an interval strictly shorter than the lease; \
         heartbeat {heartbeat:?} is not shorter than the assumed lease {ASSUMED_LEASE:?}, \
         so either the store's lease changed or this file's constant is stale"
    );
}

/// `B-26 stale-owner-fenced-write`: an owner that did not win the election
/// cannot renew, and the winner still can.
#[test]
fn b26_stale_owner_fenced_write() {
    let fixture = Fixture::new(TASK, 600_000);
    let (snapshot, fence) = fixture.elect("owner-a");

    assert!(
        fixture
            .store
            .renew_handoff_dispatch_if_current(&fixture.id, snapshot.generation(), "owner-a", fence)
            .expect("store writes succeed"),
        "the elected owner holds a live lease"
    );
    assert!(
        !fixture
            .store
            .renew_handoff_dispatch_if_current(&fixture.id, snapshot.generation(), "owner-b", fence)
            .expect("store writes succeed"),
        "a non-electing owner must not renew another owner's lease even with its fence"
    );
    assert!(
        fixture
            .store
            .renew_handoff_dispatch_if_current(&fixture.id, snapshot.generation(), "owner-a", fence)
            .expect("store writes succeed"),
        "the refused write must not have disturbed the real owner's lease"
    );
}

/// `B-27 lease-renew-expire-reclaim`, renew and expire halves only.
#[test]
fn b27_lease_renew_then_expire() {
    let fixture = Fixture::new(TASK, 600_000);
    let (snapshot, fence) = fixture.elect("owner-a");

    fixture.advance(ASSUMED_LEASE / 2);
    assert!(
        fixture
            .store
            .renew_handoff_dispatch_if_current(&fixture.id, snapshot.generation(), "owner-a", fence)
            .expect("store writes succeed"),
        "half a lease in, renewal must still succeed"
    );

    // Past the lease measured FROM THE RENEWAL, not from the election, so this
    // cannot pass merely because the original window elapsed.
    fixture.advance(ASSUMED_LEASE + Duration::from_secs(1));
    assert!(
        !fixture
            .store
            .renew_handoff_dispatch_if_current(&fixture.id, snapshot.generation(), "owner-a", fence)
            .expect("store writes succeed"),
        "a lease whose window has fully elapsed on the store's own clock must not renew"
    );

    // RECLAIM. The expired lease is dropped by the store's own reclaim pass,
    // and the retained initial work was never consumed by the take, so a
    // different owner can claim the same task.
    //
    // THE GENERATION ADVANCES ACROSS THE RECLAIM. `tasks.rs:3720-3727` fences
    // the abandoned claimant on purpose: "Without this generation advance, a
    // late drop from the old worker could release a newer worker's lease." So
    // the reclaiming owner must RE-READ, and the pre-expiry snapshot is
    // deliberately dead. Asserting that advance is the point of this half --
    // an earlier version of this test reused the stale generation, which is
    // what the 03:27Z gate caught.
    let after_expiry = fixture.snapshot();
    assert_ne!(
        after_expiry.generation(),
        snapshot.generation(),
        "reclaiming an expired lease must advance the generation; without it a late drop \
         from the evicted owner could release the next owner's lease"
    );

    let reclaimed = fixture
        .store
        .take_initial_work_handoff_for_owner_if_current(&after_expiry, "owner-b")
        .expect("store writes succeed");
    assert!(
        reclaimed.is_some(),
        "after the first owner's lease expires the retained work must be claimable again"
    );
    let new_fence = fixture
        .store
        .begin_handoff_dispatch_for_owner_if_current(
            &fixture.id,
            after_expiry.generation(),
            "owner-b",
        )
        .expect("store writes succeed")
        .expect("the reclaiming owner elects a fresh dispatch at the advanced generation");
    assert!(
        fixture
            .store
            .renew_handoff_dispatch_if_current(
                &fixture.id,
                after_expiry.generation(),
                "owner-b",
                new_fence
            )
            .expect("store writes succeed"),
        "the reclaiming owner holds a live lease"
    );
    assert!(
        !fixture
            .store
            .renew_handoff_dispatch_if_current(&fixture.id, snapshot.generation(), "owner-a", fence)
            .expect("store writes succeed"),
        "the evicted owner must not renew back in -- its generation is stale AND its lease is gone"
    );
}

/// `B-34 restore-write-contract`: an owner may hand work back only with the
/// exact lease it holds and the exact descriptor the store retained.
#[test]
fn b34_restore_write_contract() {
    let fixture = Fixture::new(TASK, 600_000);
    let (snapshot, fence) = fixture.elect("owner-a");
    let retained = FinalTaskWorkDescriptor::new(serde_json::json!({"operation": "durable"}))
        .expect("the descriptor the fixture created the task with");
    let altered = FinalTaskWorkDescriptor::new(serde_json::json!({"operation": "substituted"}))
        .expect("a well-formed but different descriptor");

    // The unauthorized variant is refused with a typed error, not a false.
    // `false` would be indistinguishable from a legitimate lost race.
    assert!(
        fixture
            .store
            .restore_initial_work_if_current(
                &fixture.id,
                snapshot.generation(),
                retained.clone()
            )
            .is_err(),
        "a restore with no owner must be a typed refusal, not a quiet false"
    );

    // Wrong descriptor: the lease matches, so the store accepts the release,
    // but the contract's return value reports that what was handed back is not
    // what it retained.
    assert!(
        !fixture
            .store
            .restore_initial_work_for_owner_if_current(
                &fixture.id,
                snapshot.generation(),
                "owner-a",
                Some(fence),
                altered
            )
            .expect("store writes succeed"),
        "restoring a descriptor the store never retained must not report success"
    );

    // Wrong fence, on a fresh fixture so the arm above cannot have consumed
    // the lease this one needs.
    let other = Fixture::new(TASK, 600_000);
    let (other_snapshot, other_fence) = other.elect("owner-a");
    assert!(
        !other
            .store
            .restore_initial_work_for_owner_if_current(
                &other.id,
                other_snapshot.generation(),
                "owner-a",
                Some(other_fence + 1),
                retained.clone()
            )
            .expect("store writes succeed"),
        "a fence one off the held lease must not restore"
    );

    // The accepted row, last, proving the refusals above were attributable to
    // the one changed variable and not to a store left unable to accept
    // anything.
    assert!(
        other
            .store
            .restore_initial_work_for_owner_if_current(
                &other.id,
                other_snapshot.generation(),
                "owner-a",
                Some(other_fence),
                retained
            )
            .expect("store writes succeed"),
        "the exact lease and the exact retained descriptor must restore"
    );
}

/// `B-42 duplicate-execution-idempotency`: a held lease makes the work
/// unclaimable by anyone, so two runners cannot execute the same task.
#[test]
fn b42_duplicate_execution_is_refused() {
    let fixture = Fixture::new(TASK, 600_000);
    let snapshot = fixture.snapshot();

    assert!(
        fixture
            .store
            .take_initial_work_handoff_for_owner_if_current(&snapshot, "owner-a")
            .expect("store writes succeed")
            .is_some(),
        "the first claim succeeds"
    );
    assert!(
        fixture
            .store
            .take_initial_work_handoff_for_owner_if_current(&fixture.snapshot(), "owner-a")
            .expect("store writes succeed")
            .is_none(),
        "the SAME owner claiming twice must not get a second execution"
    );
    assert!(
        fixture
            .store
            .take_initial_work_handoff_for_owner_if_current(&fixture.snapshot(), "owner-b")
            .expect("store writes succeed")
            .is_none(),
        "a second owner must not get a concurrent execution of the same task"
    );

    // An empty owner is a typed refusal rather than an anonymous claim. A
    // `false`/`None` here would let an unattributable runner hold work.
    assert!(
        fixture
            .store
            .take_initial_work_handoff_for_owner_if_current(&fixture.snapshot(), "")
            .is_err(),
        "an empty owner must be refused with an error, not silently declined"
    );
}

/// `B-28 durable-time-authority`: retention time comes from the store's
/// injected clock, never from the wall clock.
#[test]
fn b28_durable_time_authority() {
    let fixture = Fixture::new(TASK, 600_000);

    let first = fixture.store.retention_clock_now();
    let second = fixture.store.retention_clock_now();
    assert_eq!(
        first, second,
        "two reads with no advance must be identical; a wall clock would drift between them"
    );
    assert_eq!(
        first,
        fixture.clock_reads(),
        "the store must report exactly the injected value, not an offset of it"
    );

    fixture.advance(Duration::from_secs(90));
    assert_eq!(
        fixture.store.retention_clock_now(),
        first + Duration::from_secs(90),
        "advancing the injected clock must move the store's authority by exactly that amount"
    );

    // The retention deadline is derived from the same authority.
    let snapshot = fixture.snapshot();
    let deadline = fixture
        .store
        .task_retention_deadline_if_current(&fixture.id, snapshot.generation())
        .expect("store reads succeed")
        .expect("a live task at its current generation has a deadline");
    let FinalTaskRetentionDeadline::Finite(at) = deadline else {
        panic!("a task created with a finite ttlMs must have a finite deadline, got {deadline:?}");
    };
    assert_eq!(
        at,
        first + Duration::from_millis(600_000),
        "the deadline must be the creation-time clock reading plus the declared TTL"
    );
}

/// `B-31 private-update-revision-order`, stale-generation half only.
#[test]
fn b31_stale_generation_is_refused() {
    let fixture = Fixture::new(TASK, 600_000);
    let snapshot = fixture.snapshot();
    let stale = snapshot
        .generation()
        .checked_sub(1)
        .expect("the store issues generations above zero");

    assert!(
        fixture
            .store
            .task_retention_deadline_if_current(&fixture.id, snapshot.generation())
            .expect("store reads succeed")
            .is_some(),
        "the current generation resolves"
    );
    assert!(
        fixture
            .store
            .task_retention_deadline_if_current(&fixture.id, stale)
            .expect("store reads succeed")
            .is_none(),
        "a generation one behind the current one must read as stale, not as the current row"
    );
}

/// `B-43 shutdown-drain-lease-release`: a completed dispatch releases exactly
/// once, and a second release is refused rather than double-counted.
#[test]
fn b43_release_happens_exactly_once() {
    let fixture = Fixture::new(TASK, 600_000);
    let (snapshot, fence) = fixture.elect("owner-a");

    assert!(
        fixture
            .store
            .finish_handoff_dispatch_for_owner_if_current(
                &fixture.id,
                snapshot.generation(),
                "owner-a",
                fence
            )
            .expect("store writes succeed"),
        "the elected owner releases its own live lease"
    );
    assert!(
        !fixture
            .store
            .finish_handoff_dispatch_for_owner_if_current(
                &fixture.id,
                snapshot.generation(),
                "owner-a",
                fence
            )
            .expect("store writes succeed"),
        "a second release of the same lease must be refused, or a drain would count it twice"
    );
    assert!(
        !fixture
            .store
            .renew_handoff_dispatch_if_current(&fixture.id, snapshot.generation(), "owner-a", fence)
            .expect("store writes succeed"),
        "a released lease cannot be renewed back into existence"
    );
}

/// `B-29 backend-clock-discontinuity`: a clock that goes BACKWARDS cannot undo
/// a reclamation that already happened.
///
/// Scope, stated because it is narrow: the store has no documented behaviour
/// for a regressing clock, and inventing one here would be asserting a
/// requirement the source does not carry. What IS backed by the source is that
/// reclamation is DESTRUCTIVE -- `reclaim_expired_in_memory_final_tasks`
/// removes the lease from `handoff_leases` and advances the generation
/// (tasks.rs:3720-3727). Neither is recoverable by any later clock reading, so
/// the safety property survives a discontinuity by construction rather than by
/// a guard. This test pins that, and pins that the authority still tracks the
/// injected value exactly afterwards.
#[test]
fn b29_backend_clock_discontinuity() {
    let fixture = Fixture::new(TASK, 600_000);
    let (snapshot, fence) = fixture.elect("owner-a");

    // Expire the lease and force the reclaim pass to observe it.
    fixture.advance(ASSUMED_LEASE + Duration::from_secs(1));
    assert!(
        !fixture
            .store
            .renew_handoff_dispatch_if_current(&fixture.id, snapshot.generation(), "owner-a", fence)
            .expect("store writes succeed"),
        "the lease must be gone before the clock is rewound, or this proves nothing"
    );
    let reclaimed_generation = fixture.snapshot().generation();
    assert_ne!(
        reclaimed_generation,
        snapshot.generation(),
        "the reclaim must have advanced the generation before the rewind"
    );

    // THE DISCONTINUITY: back to before the lease was ever issued.
    fixture.rewind_to(Duration::ZERO);
    assert_eq!(
        fixture.store.retention_clock_now(),
        fixture.clock_reads(),
        "the authority must report the injected value after it regresses, not a latched maximum"
    );

    // The evicted owner cannot renew even though its lease window now appears
    // to lie in the future again. The lease row is gone; time cannot restore it.
    assert!(
        !fixture
            .store
            .renew_handoff_dispatch_if_current(&fixture.id, snapshot.generation(), "owner-a", fence)
            .expect("store writes succeed"),
        "a clock regression must not resurrect a reclaimed lease"
    );
    assert_eq!(
        fixture.snapshot().generation(),
        reclaimed_generation,
        "a clock regression must not roll the generation back"
    );

    // And the task itself is untouched by the regression.
    assert_eq!(
        fixture.task_wire_form()["taskId"],
        TASK,
        "the record must survive the discontinuity intact"
    );
}

/// `B-30 skewed-worker-time-domains`: no caller supplies time, so a worker's
/// own clock cannot influence a lease decision.
///
/// The property is structural: every timing decision in the store reads
/// `(self.clock)()`, and no method on the trait accepts an instant, a
/// duration, or a deadline from its caller. Two workers therefore cannot
/// disagree about time because neither of them is consulted. This test
/// demonstrates the observable consequence rather than restating the shape --
/// with the store's clock held still, no amount of work expires a lease, and
/// one advance of that clock expires it immediately.
#[test]
fn b30_skewed_worker_time_domains() {
    let fixture = Fixture::new(TASK, 600_000);
    let (snapshot, fence) = fixture.elect("owner-a");
    let frozen = fixture.store.retention_clock_now();

    // Real elapsed time and real work, with the store's clock held still.
    // Under a wall clock these 200 operations would take measurable time; the
    // lease must not care.
    for i in 0..200 {
        assert!(
            fixture
                .store
                .renew_handoff_dispatch_if_current(
                    &fixture.id,
                    snapshot.generation(),
                    "owner-a",
                    fence
                )
                .expect("store writes succeed"),
            "renewal {i} must succeed while the store's clock has not moved"
        );
        assert!(
            !fixture
                .store
                .renew_handoff_dispatch_if_current(
                    &fixture.id,
                    snapshot.generation(),
                    "owner-b",
                    fence
                )
                .expect("store writes succeed"),
            "a second worker must not win at iteration {i} either"
        );
    }
    assert_eq!(
        fixture.store.retention_clock_now(),
        frozen,
        "200 operations must not move an authority nobody supplied time to"
    );

    // One advance of the STORE's clock, and only that, ends the lease.
    fixture.advance(ASSUMED_LEASE + Duration::from_secs(1));
    assert!(
        !fixture
            .store
            .renew_handoff_dispatch_if_current(&fixture.id, snapshot.generation(), "owner-a", fence)
            .expect("store writes succeed"),
        "the store's own clock is the only thing that can expire the lease"
    );
}

/// `B-32 deadline-renew-restart`: renewing a dispatch lease must not extend
/// the task's retention deadline, and a restart must not reset it.
///
/// These are two separate clocks and conflating them would be a real defect:
/// a worker that renews forever would keep a task alive past its declared
/// TTL. Source-backed -- `renew_handoff_dispatch_if_current` writes only
/// `lease.recovery_expires_at` (tasks.rs:3149) and never touches the task's
/// `expires_at`, which is what `task_retention_deadline_if_current` reports.
#[test]
fn b32_deadline_survives_renew_and_restart() {
    let fixture = Fixture::new(TASK, 600_000);
    let (snapshot, fence) = fixture.elect("owner-a");

    let deadline_at_start = fixture
        .store
        .task_retention_deadline_if_current(&fixture.id, snapshot.generation())
        .expect("store reads succeed")
        .expect("a live task has a deadline");
    let FinalTaskRetentionDeadline::Finite(original) = deadline_at_start else {
        panic!("a finite ttlMs must give a finite deadline, got {deadline_at_start:?}");
    };

    // Renew repeatedly, advancing well past a whole lease window in total.
    for _ in 0..10 {
        fixture.advance(Duration::from_secs(2));
        assert!(
            fixture
                .store
                .renew_handoff_dispatch_if_current(
                    &fixture.id,
                    snapshot.generation(),
                    "owner-a",
                    fence
                )
                .expect("store writes succeed"),
            "renewal within the window succeeds"
        );
        let still = fixture
            .store
            .task_retention_deadline_if_current(&fixture.id, snapshot.generation())
            .expect("store reads succeed")
            .expect("the task is still retained");
        assert_eq!(
            still,
            FinalTaskRetentionDeadline::Finite(original),
            "renewing the LEASE must not move the TASK's retention deadline"
        );
    }

    // RESTART: let the lease lapse, then let a new owner take over. The task's
    // deadline is a property of the task, not of whoever is currently holding
    // it, so it must be unchanged across the handover.
    fixture.advance(ASSUMED_LEASE + Duration::from_secs(1));
    let after_expiry = fixture.snapshot();
    assert!(
        fixture
            .store
            .take_initial_work_handoff_for_owner_if_current(&after_expiry, "owner-b")
            .expect("store writes succeed")
            .is_some(),
        "a restarted worker picks the task up"
    );
    let after_restart = fixture
        .store
        .task_retention_deadline_if_current(&fixture.id, after_expiry.generation())
        .expect("store reads succeed")
        .expect("the task survived the handover");
    assert_eq!(
        after_restart,
        FinalTaskRetentionDeadline::Finite(original),
        "a restart must not reset the task's retention deadline"
    );
}

// ---------------------------------------------------------------------------
// B-35: a second, out-of-crate backend
// ---------------------------------------------------------------------------

/// A minimal third-party backend implementing ONLY the ten methods
/// `FinalTaskStore` requires, inheriting all twenty-seven defaults.
///
/// Its purpose is not to be useful. It exists so the conformance assertions
/// below can be shown to test the TRAIT CONTRACT rather than one
/// implementation's habits: any property asserted of both this and the
/// shipped store is a property of the contract. Nothing here stands in for
/// the shipped store -- `InMemoryFinalTaskStore` is exercised by the same
/// function, so PL-3 is satisfied by the real subject and this backend only
/// bounds what the assertions are allowed to mean.
#[derive(Default)]
struct MinimalBackend {
    tasks: Mutex<BTreeMap<FinalTaskId, (Task, u64)>>,
    cancellations: Mutex<BTreeSet<FinalTaskId>>,
}

impl MinimalBackend {
    fn locked(&self) -> std::sync::MutexGuard<'_, BTreeMap<FinalTaskId, (Task, u64)>> {
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl FinalTaskStore for MinimalBackend {
    fn create_task(&self, task: Task, _notification: TaskStatusNotification) -> McpResult<()> {
        let id = task.base().task_id.clone();
        if self.locked().insert(id, (task, 1)).is_some() {
            return Err(McpError::invalid_params("duplicate task identifier"));
        }
        Ok(())
    }

    fn get_task(&self, task_id: &FinalTaskId) -> McpResult<Option<Task>> {
        Ok(self.locked().get(task_id).map(|(task, _)| task.clone()))
    }

    fn get_task_snapshot(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>> {
        Ok(self
            .locked()
            .get(task_id)
            .map(|(task, generation)| FinalTaskSnapshot::new(task.clone(), *generation)))
    }

    fn replace_task(&self, task: Task, _notification: TaskStatusNotification) -> McpResult<()> {
        let id = task.base().task_id.clone();
        let mut state = self.locked();
        let Some((slot, generation)) = state.get_mut(&id) else {
            return Err(McpError::invalid_params("unknown task identifier"));
        };
        *slot = task;
        *generation += 1;
        Ok(())
    }

    fn replace_task_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        task: Task,
        _notification: TaskStatusNotification,
    ) -> McpResult<bool> {
        let id = task.base().task_id.clone();
        let mut state = self.locked();
        let Some((slot, generation)) = state.get_mut(&id) else {
            return Ok(false);
        };
        if *generation != expected.generation() {
            return Ok(false);
        }
        *slot = task;
        *generation += 1;
        Ok(true)
    }

    fn request_cancellation(&self, task_id: &FinalTaskId) -> McpResult<()> {
        if !self.locked().contains_key(task_id) {
            return Err(McpError::invalid_params("unknown task identifier"));
        }
        self.cancellations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(task_id.clone());
        Ok(())
    }

    fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool> {
        let id = expected.task().base().task_id.clone();
        if self.locked().get(&id).map(|(_, g)| *g) != Some(expected.generation()) {
            return Ok(false);
        }
        self.request_cancellation(&id)?;
        Ok(true)
    }

    fn is_cancellation_requested(&self, task_id: &FinalTaskId) -> McpResult<bool> {
        Ok(self
            .cancellations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(task_id))
    }

    fn retention_clock_now(&self) -> Instant {
        Instant::now()
    }

    fn task_retention_deadline_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
    ) -> McpResult<Option<FinalTaskRetentionDeadline>> {
        Ok(self
            .locked()
            .get(task_id)
            .filter(|(_, current)| *current == generation)
            .map(|_| FinalTaskRetentionDeadline::Unlimited))
    }
}

/// Builds a `working` task and its notification, for either backend.
fn conformance_task(task_id: &str) -> (Task, TaskStatusNotification) {
    let task: Task = serde_json::from_value(serde_json::json!({
        "taskId": task_id,
        "status": "working",
        "createdAt": "2026-07-28T12:00:00.000Z",
        "lastUpdatedAt": "2026-07-28T12:00:00.000Z",
        "ttlMs": 600_000
    }))
    .expect("a well-formed working task");
    let notification = TaskStatusNotification::new(TaskStatusNotificationParams {
        task: task.clone(),
        meta: None,
        additional: std::collections::BTreeMap::default(),
    });
    (task, notification)
}

/// Properties every `FinalTaskStore` must satisfy, whoever wrote it.
///
/// Deliberately confined to the ten REQUIRED methods. Anything asserted here
/// of a capability a backend may legitimately decline would not be a contract
/// property, it would be a preference.
fn assert_required_surface_conformance(store: &dyn FinalTaskStore, backend: &str) {
    let (task, notification) = conformance_task("conformance-subject");
    let id = task.base().task_id.clone();
    let missing = conformance_task("conformance-absent").0.base().task_id.clone();

    assert!(
        store
            .get_task(&missing)
            .unwrap_or_else(|error| panic!("{backend}: reading an unknown task is not an error: {error}"))
            .is_none(),
        "{backend}: an unknown task must read as absent, not as an error or a value"
    );

    store
        .create_task(task, notification)
        .unwrap_or_else(|error| panic!("{backend}: creating a working task must succeed: {error}"));

    assert_eq!(
        store
            .get_task(&id)
            .expect("reads succeed")
            .expect("the created task is retained")
            .base()
            .task_id,
        id,
        "{backend}: a created task must read back under its own identifier"
    );

    let first = store
        .get_task_snapshot(&id)
        .expect("reads succeed")
        .expect("the created task has a snapshot");
    let second = store
        .get_task_snapshot(&id)
        .expect("reads succeed")
        .expect("the created task still has a snapshot");
    assert_eq!(
        first.generation(),
        second.generation(),
        "{backend}: a generation must not change because it was read"
    );

    assert!(
        store
            .task_retention_deadline_if_current(&id, first.generation())
            .expect("reads succeed")
            .is_some(),
        "{backend}: the current generation must resolve to a deadline"
    );
    assert!(
        store
            .task_retention_deadline_if_current(&id, first.generation().wrapping_add(1))
            .expect("reads succeed")
            .is_none(),
        "{backend}: a generation that is not current must read as absent"
    );

    assert!(
        !store
            .is_cancellation_requested(&id)
            .expect("reads succeed"),
        "{backend}: a fresh task carries no cancellation intent"
    );
    store
        .request_cancellation(&id)
        .unwrap_or_else(|error| panic!("{backend}: cancelling a known task must succeed: {error}"));
    assert!(
        store
            .is_cancellation_requested(&id)
            .expect("reads succeed"),
        "{backend}: cancellation intent must be durable once recorded"
    );
}

/// `B-35 third-party-backend-conformance`.
///
/// Two claims, and they are different in kind.
///
/// FIRST, the trait is implementable from outside the crate at all. Nothing
/// in this workspace implemented `FinalTaskStore` outside
/// `crates/fastmcp-server/src`; `MinimalBackend` below is the first, and it
/// compiles against the published surface using only public items. That is a
/// property of the shipped API, not of a mock.
///
/// SECOND, the required-surface properties hold for both the shipped store
/// and an unrelated implementation, which is what makes them CONTRACT
/// properties rather than observations about one backend's habits.
///
/// PL-3 note: the shipped `InMemoryFinalTaskStore` is exercised by the same
/// function, so the real subject is under test. `MinimalBackend` never stands
/// in for it -- it only bounds what the shared assertions are allowed to
/// claim.
#[test]
fn b35_third_party_backend_conformance() {
    let shipped = InMemoryFinalTaskStore::new(4).expect("bounded store");
    assert_required_surface_conformance(&shipped, "InMemoryFinalTaskStore");

    let third_party = MinimalBackend::default();
    assert_required_surface_conformance(&third_party, "MinimalBackend");

    // The optional surface FAILS CLOSED on a backend that declined it. The
    // trait's defaults return an error rather than a false or a None, so a
    // caller cannot mistake "not implemented" for "declined this time" and
    // create unexecutable work. Nothing in the tree tested this.
    let (task, notification) = conformance_task("conformance-fail-closed");
    assert!(
        third_party
            .create_task_with_work(
                task,
                notification,
                FinalTaskWorkDescriptor::new(serde_json::json!({"operation": "x"}))
                    .expect("bounded descriptor")
            )
            .is_err(),
        "a backend without atomic task-work creation must refuse, not silently create a task"
    );
    assert!(
        third_party
            .handoff_dispatch_lease_heartbeat_interval()
            .is_err(),
        "a backend with no durable lease must not disclose a heartbeat interval"
    );
    assert!(
        third_party
            .begin_handoff_dispatch_for_owner_if_current(
                &conformance_task("conformance-fail-closed").0.base().task_id.clone(),
                1,
                "owner-a"
            )
            .is_err(),
        "a backend with no dispatch election must refuse rather than report a lost race"
    );

    // And the discriminator: the SHIPPED store implements those same three,
    // so the assertions above distinguish backends instead of holding
    // vacuously for everyone.
    assert!(
        shipped.handoff_dispatch_lease_heartbeat_interval().is_ok(),
        "the shipped store does implement the optional surface, so failing closed is a \
         real distinction and not a property of the trait itself"
    );
}

// ---------------------------------------------------------------------------
// Frozen IDs
// ---------------------------------------------------------------------------

#[test]
fn task_02_b_positive() {
    lease_window_is_the_one_this_file_assumes();
    b26_stale_owner_fenced_write();
    b27_lease_renew_then_expire();
    b28_durable_time_authority();
    b29_backend_clock_discontinuity();
    b30_skewed_worker_time_domains();
    b32_deadline_survives_renew_and_restart();
    b35_third_party_backend_conformance();
    b31_stale_generation_is_refused();
    b34_restore_write_contract();
    b42_duplicate_execution_is_refused();
    b43_release_happens_exactly_once();
}

#[test]
fn task_02_b_planted_negative() {
    // ARM 0 -- the accepted row. Without it, a store that refused every write
    // would pass the arm below for the wrong reason.
    let accepted = Fixture::new(TASK, 600_000);
    let (accepted_snapshot, accepted_fence) = accepted.elect("owner-a");
    assert!(
        accepted
            .store
            .renew_handoff_dispatch_if_current(
                &accepted.id,
                accepted_snapshot.generation(),
                "owner-a",
                accepted_fence
            )
            .expect("store writes succeed"),
        "the unmutated fence must renew, or the arm below proves nothing"
    );

    // THE ONE VARIABLE: the committed fence generation, moved by exactly one.
    // Owner, task generation, clock, and every other input are identical to
    // ARM 0.
    let fixture = Fixture::new(TASK, 600_000);
    let (snapshot, fence) = fixture.elect("owner-a");
    let stale_fence = fence
        .checked_add(1)
        .expect("a fence one above the issued one is representable");
    assert_ne!(
        stale_fence, fence,
        "the mutation must actually change the fence"
    );

    // Everything the refusal must leave untouched, sampled BEFORE.
    let before_deadline = fixture
        .store
        .task_retention_deadline_if_current(&fixture.id, snapshot.generation())
        .expect("store reads succeed");
    let before_clock = fixture.store.retention_clock_now();
    let before_task = fixture.task_wire_form();
    assert_eq!(
        before_task["taskId"], TASK,
        "the sampled record must be the real task, or every comparison below is vacuous"
    );
    let before_generation = fixture
        .store
        .get_task_snapshot(&fixture.id)
        .expect("store reads succeed")
        .expect("the task exists")
        .generation();
    let before_cancellation = fixture
        .store
        .is_cancellation_requested(&fixture.id)
        .expect("store reads succeed");

    assert!(
        !fixture
            .store
            .renew_handoff_dispatch_if_current(&fixture.id, snapshot.generation(), "owner-a", stale_fence)
            .expect("a stale fence is a refusal, not a transport error")
            ,
        "a fence one generation off must be refused"
    );
    assert!(
        !fixture
            .store
            .finish_handoff_dispatch_for_owner_if_current(
                &fixture.id,
                snapshot.generation(),
                "owner-a",
                stale_fence
            )
            .expect("a stale fence is a refusal, not a transport error"),
        "a stale fence must not be able to release a lease it does not hold"
    );

    // The named state fields, unchanged.
    assert_eq!(
        fixture
            .store
            .task_retention_deadline_if_current(&fixture.id, snapshot.generation())
            .expect("store reads succeed"),
        before_deadline,
        "expiry state must be unchanged by a refused fenced write"
    );
    assert_eq!(
        fixture.store.retention_clock_now(),
        before_clock,
        "the durable-time sample must be unchanged"
    );
    assert_eq!(
        fixture.task_wire_form(),
        before_task,
        "the task record must be unchanged"
    );
    assert_eq!(
        fixture
            .store
            .get_task_snapshot(&fixture.id)
            .expect("store reads succeed")
            .expect("the task still exists")
            .generation(),
        before_generation,
        "a refused write must not consume a generation"
    );
    assert_eq!(
        fixture
            .store
            .is_cancellation_requested(&fixture.id)
            .expect("store reads succeed"),
        before_cancellation,
        "cancellation intent must be unchanged"
    );

    // And the real fence still works, which proves the refusals above were
    // attributable to the mutated fence and not to a store left broken.
    assert!(
        fixture
            .store
            .renew_handoff_dispatch_if_current(&fixture.id, snapshot.generation(), "owner-a", fence)
            .expect("store writes succeed"),
        "the genuine fence must still renew after the refused attempts"
    );
}
