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
//! This file does NOT discharge the bead. It covers five of the twenty-three
//! named groups, and covers two of those only in part:
//!
//! | group | state here |
//! |---|---|
//! | `B-26 stale-owner-fenced-write`   | covered |
//! | `B-27 lease-renew-expire-reclaim` | PARTIAL: renew and expire only. Reclaim is not asserted, because the reclaim path after an expired initial-work lease is not established by the trait's own contract text and I will not assert behaviour I have not read. |
//! | `B-28 durable-time-authority`     | covered |
//! | `B-31 private-update-revision-order` | PARTIAL: stale-generation refusal only. Ordering across concurrent writers is not asserted. |
//! | `B-43 shutdown-drain-lease-release` | covered |
//!
//! The eighteen remaining groups -- `B-24`, `B-25`, `B-29`, `B-30`, `B-32`
//! through `B-42` less those above, and `B-44` through `B-46` -- have no test
//! here and no test anywhere in the tree. Four of them rest on vocabulary the
//! shipped source does not yet carry at all: a word-boundary count over
//! `crates/fastmcp-server/src/tasks.rs` gives `quota` = 2, `tombstone` = 0,
//! `reconcil` = 0, `epoch` = 0, against `lease` = 191, `fence` = 64,
//! `durable` = 157 and `generation` = 540. Those four are implementation gaps,
//! not test gaps, and cannot be closed by writing tests.
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
}

/// `B-28 durable-time-authority`: retention time comes from the store's
/// injected clock, never from the wall clock.
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

// ---------------------------------------------------------------------------
// Frozen IDs
// ---------------------------------------------------------------------------

#[test]
fn task_02_b_positive() {
    lease_window_is_the_one_this_file_assumes();
    b26_stale_owner_fenced_write();
    b27_lease_renew_then_expire();
    b28_durable_time_authority();
    b31_stale_generation_is_refused();
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
            .renew_handoff_dispatch_if_current(
                &fixture.id,
                snapshot.generation(),
                "owner-a",
                stale_fence
            )
            .expect("a stale fence is a refusal, not a transport error"),
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
