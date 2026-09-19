//! Public Linux file/async composition. Real descriptor-relative files, locks,
//! rename/fsync and the production coordinator are used throughout. The anchor
//! is an explicitly provisioned, in-memory fault fixture, NOT an independently
//! durable provider. Opaque payload fixtures do not qualify encryption, OAuth
//! token persistence, process-restart anchor custody or deployment rollback.
#![cfg(target_os = "linux")]

use std::fs::{self, File, Permissions};
use std::future::{Future, poll_fn};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::task::Poll;
use std::thread::ThreadId;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use fastmcp_core::ingress::{SecurityPartitionDescriptor, VerifiedAudienceBinding, VerifiedIdentityFacts, VerifiedIngressAuthentication};
use fastmcp_core::partition::{CredentialStoreKey, DurableOwnerKey, PartitionAuthorization};
use fastmcp_core::runtime::ProcessGenerationGuard;
use fastmcp_client::http_auth::secure_file::AtomicFileError;
use fastmcp_client::http_auth::secure_file::slot::{CredentialSlotError, SlotRecoveryOutcome};
use fastmcp_client::http_auth::secure_file::slot::coordinator::{
    CoordinatedSlotError, CredentialAnchorBinding, CredentialAnchorError,
    CredentialAnchorSnapshot, CredentialAnchorState, CredentialCommitAnchor,
};
use fastmcp_client::http_auth::secure_file::slot::coordinator::asynchronous::{
    AsyncCoordinatedCredentialSlot, CredentialIoError, CredentialIoLane, CredentialIoLimits,
    CredentialIoSnapshot, CredentialSlotOpen, CredentialSlotTask,
};

const NAMESPACE: &str = "async-slot-test";
const PAYLOAD: &[u8] = &[0x8a, 0x01, 0xff, 0x00, 0x41, 0x09];
const LIMIT: usize = 4096;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("fastmcp-async-slot-{}-{nonce}-{}",
            std::process::id(), NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn handle(&self) -> File { File::open(&self.0).unwrap() }
    fn contents(&self) -> Option<Vec<u8>> {
        match fs::read(self.0.join("credential")) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("fixture read failed: {error}"),
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        // Only these test-owned leaves are removed, never repository files.
        let _ = fs::remove_file(self.0.join("credential"));
        let _ = fs::remove_file(self.0.join(".credential.lock"));
        let _ = fs::remove_dir(&self.0);
    }
}

fn identity(subject: &str) -> (CredentialStoreKey, PartitionAuthorization) {
    let ingress = VerifiedIngressAuthentication::from_verified_provider_output(VerifiedIdentityFacts {
        provider: "fixture-provider", configuration_generation: 7,
        issuer: "https://issuer.example", canonical_resource: "https://mcp.example/mcp",
        verified_audience_binding: VerifiedAudienceBinding::OAuth {
            canonical_resource: "https://mcp.example/mcp".to_owned(), validated_audience: "https://mcp.example/mcp".to_owned(),
            audience_policy_id: "fixture-policy".to_owned(), audience_policy_revision: 3,
            provider: "fixture-provider".to_owned(), configuration_generation: 7,
        },
        tenant: "fixture-tenant", subject_or_principal: subject, authorized_party_or_client: "fixture-client",
        verified_claims: &[], auth_policy_revision: 4, trust_generation: 2,
    }).unwrap();
    let descriptor = SecurityPartitionDescriptor::from_verified_ingress(&ingress).to_partition_descriptor().unwrap();
    let key = CredentialStoreKey::derive(&descriptor, "test-store", "refresh", "test-instance").unwrap();
    let owner = DurableOwnerKey::derive(&descriptor, 1).unwrap();
    (key, PartitionAuthorization::current(&descriptor, &owner))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pause { Read, Prepared, Settled }
struct Gate { entered: AtomicBool, released: Mutex<bool>, condition: Condvar }
impl Gate {
    fn new() -> Self { Self { entered: AtomicBool::new(false), released: Mutex::new(false), condition: Condvar::new() } }
    fn block(&self) {
        self.entered.store(true, Ordering::Release);
        let held = self.released.lock().unwrap();
        let (held, _) = self.condition.wait_timeout_while(held, Duration::from_secs(5), |released| !*released).unwrap();
        assert!(*held, "fixture anchor exceeded its bounded gate");
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }
    async fn wait_entered(&self, cx: &Cx) {
        let deadline = cx.now().saturating_add_nanos(2_000_000_000);
        asupersync::time::timeout_at(deadline, async {
            while !self.entered.load(Ordering::Acquire) {
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
        }).await.expect("fixture anchor entered on its blocking worker");
    }
}
struct Release(Arc<Gate>);
impl Drop for Release { fn drop(&mut self) { self.0.release(); } }
struct AnchorState {
    snapshot: CredentialAnchorSnapshot,
    reads: usize,
    writes: usize,
    threads: Vec<ThreadId>,
    pause: Option<(Pause, Arc<Gate>)>,
    uncertain_prepare: bool,
}
#[derive(Clone)]
struct Anchor(Arc<Mutex<AnchorState>>);
impl Anchor {
    fn new(key: &CredentialStoreKey, auth: &PartitionAuthorization) -> Self {
        let binding = CredentialAnchorBinding::for_store(NAMESPACE, key, auth).unwrap();
        Self(Arc::new(Mutex::new(AnchorState {
            snapshot: CredentialAnchorSnapshot::new(binding, 0, CredentialAnchorState::Stable(None)),
            reads: 0, writes: 0, threads: vec![], pause: None, uncertain_prepare: false,
        })))
    }
    fn arm(&self, point: Pause) -> Release {
        let gate = Arc::new(Gate::new());
        self.0.lock().unwrap().pause = Some((point, gate.clone()));
        Release(gate)
    }
    fn counts(&self) -> (usize, usize) { let s = self.0.lock().unwrap(); (s.reads, s.writes) }
    fn snapshot(&self) -> CredentialAnchorSnapshot { self.0.lock().unwrap().snapshot }
}
fn gate(state: &mut AnchorState, point: Pause) -> Option<Arc<Gate>> {
    if state.pause.as_ref().is_some_and(|(selected, _)| *selected == point) {
        state.pause.take().map(|(_, gate)| gate)
    } else { None }
}
impl CredentialCommitAnchor for Anchor {
    fn current(&mut self, cx: &Cx, binding: &CredentialAnchorBinding)
        -> Result<CredentialAnchorSnapshot, CredentialAnchorError>
    {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let (snapshot, pause) = {
            let mut s = self.0.lock().unwrap();
            if s.snapshot.binding() != *binding { return Err(CredentialAnchorError::NotProvisioned); }
            s.reads += 1;
            s.threads.push(std::thread::current().id());
            (s.snapshot, gate(&mut s, Pause::Read))
        };
        if let Some(pause) = pause { pause.block(); }
        Ok(snapshot)
    }
    fn compare_exchange(&mut self, cx: &Cx, expected: &CredentialAnchorSnapshot, next: CredentialAnchorState)
        -> Result<CredentialAnchorSnapshot, CredentialAnchorError>
    {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let (snapshot, pause, uncertain) = {
            let mut s = self.0.lock().unwrap();
            if s.snapshot != *expected { return Err(CredentialAnchorError::Conflict); }
            let sequence = expected.sequence().checked_add(1).ok_or(CredentialAnchorError::Unavailable)?;
            s.snapshot = CredentialAnchorSnapshot::new(expected.binding(), sequence, next);
            s.writes += 1;
            s.threads.push(std::thread::current().id());
            let prepared = matches!(next, CredentialAnchorState::Pending(_));
            let uncertain = prepared && s.uncertain_prepare;
            if uncertain { s.uncertain_prepare = false; }
            let pause = gate(&mut s, if prepared { Pause::Prepared } else { Pause::Settled });
            (s.snapshot, pause, uncertain)
        };
        if let Some(pause) = pause { pause.block(); }
        if uncertain { Err(CredentialAnchorError::Uncertain) } else { Ok(snapshot) }
    }
}
struct Fixture {
    directory: Directory, key: CredentialStoreKey, auth: PartitionAuthorization,
    anchor: Anchor, lane: CredentialIoLane,
}
impl Fixture {
    fn new() -> Self {
        Self::on_lane(CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(), CredentialIoLimits::default()).unwrap())
    }
    fn on_lane(lane: CredentialIoLane) -> Self {
        let (key, auth) = identity("alice");
        let anchor = Anchor::new(&key, &auth);
        Self { directory: Directory::new(), key, auth, anchor, lane }
    }
    fn start_open(&self, cx: &Cx) -> Result<CredentialSlotTask<CredentialSlotOpen<Anchor>>, CredentialIoError> {
        AsyncCoordinatedCredentialSlot::open(cx, &self.lane,
            self.directory.handle(), "credential".to_owned(), LIMIT, self.key, self.auth,
            NAMESPACE.to_owned(), self.anchor.clone())
    }
    async fn open(&self, cx: &Cx) -> AsyncCoordinatedCredentialSlot<Anchor> {
        let (owner, recovery) = done(cx, self.start_open(cx)).await.unwrap();
        assert_eq!(recovery, None);
        wait_jobs(cx, &self.lane).await;
        owner
    }
}
async fn done<T>(cx: &Cx, task: Result<CredentialSlotTask<T>, CredentialIoError>) -> T {
    let mut task = task.unwrap();
    task.wait(cx).await.unwrap()
}
async fn wait_jobs(cx: &Cx, lane: &CredentialIoLane) {
    asupersync::time::timeout_at(cx.now().saturating_add_nanos(2_000_000_000), async {
        loop {
            let state = lane.snapshot().unwrap();
            if state.operations == 0 && state.closes == 0 { break; }
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
        }
    }).await.expect("credential jobs released their charges");
}
fn run<F, Fut>(blocking: bool, scenario: F)
where F: FnOnce(Cx) -> Fut, Fut: Future<Output = ()>,
{
    let builder = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap());
    let builder = if blocking { builder.blocking_threads(1, 4) } else { builder.blocking_threads(0, 0) };
    builder.build().unwrap().block_on(async move {
        let cx = Cx::current().unwrap();
        let deadline = cx.now().saturating_add_nanos(15_000_000_000);
        asupersync::time::timeout_at(deadline, Box::pin(scenario(cx))).await.unwrap();
    });
}

#[test]
fn async_slot_persists_reopens_and_tombstones_before_payload_delivery() {
    run(true, |cx| async move {
        let f = Fixture::new();
        let poller = std::thread::current().id();
        let owner = f.open(&cx).await;
        let (owner, outcome) = done(&cx, owner.replace(&cx, f.auth, None, PAYLOAD.to_vec())).await.into_parts();
        let revision = outcome.unwrap();
        assert_eq!(revision.generation(), 1);
        assert_eq!(f.anchor.snapshot().state(), CredentialAnchorState::Stable(Some(revision)));
        done(&cx, owner.close(&cx)).await;
        let owner = f.open(&cx).await;
        assert_eq!(owner.revision(), Some(revision));
        let (owner, loaded) = done(&cx, owner.load(&cx, f.auth)).await.into_parts();
        assert_eq!(loaded.unwrap().as_deref(), Some(PAYLOAD));
        let (owner, outcome) = done(&cx, owner.take(&cx, f.auth, revision)).await.into_parts();
        let committed = outcome.unwrap();
        let tombstone = committed.revision();
        assert_eq!(tombstone.generation(), 2);
        assert_eq!(f.anchor.snapshot().state(), CredentialAnchorState::Stable(Some(tombstone)));
        assert_eq!(committed.into_consumed().as_deref(), Some(PAYLOAD));
        done(&cx, owner.close(&cx)).await;
        let owner = f.open(&cx).await;
        assert_eq!(owner.revision(), Some(tombstone));
        let (owner, loaded) = done(&cx, owner.load(&cx, f.auth)).await.into_parts();
        assert_eq!(loaded.unwrap(), None);
        done(&cx, owner.close(&cx)).await;
        let anchor = f.anchor.0.lock().unwrap();
        assert_eq!(anchor.writes, 4);
        assert!(anchor.threads.iter().all(|worker| *worker != poller));
    });
}

#[test]
fn async_slot_rejections_preserve_owner_file_and_anchor_without_mutation() {
    run(true, |cx| async move {
        let f = Fixture::new();
        let owner = f.open(&cx).await;
        let (owner, outcome) = done(&cx, owner.replace(&cx, f.auth, None, PAYLOAD.to_vec())).await.into_parts();
        let revision = outcome.unwrap();
        let bytes = f.directory.contents();
        let snapshot = f.anchor.snapshot();
        let counts = f.anchor.counts();
        let (_, foreign) = identity("bob");
        let (owner, refused) = done(&cx, owner.load(&cx, foreign)).await.into_parts();
        assert_eq!(refused.err(), Some(CoordinatedSlotError::Slot(CredentialSlotError::BindingMismatch)));
        assert_eq!(f.anchor.counts(), counts, "foreign authorization cannot even query the anchor");
        let (owner, refused) = done(&cx, owner.replace(&cx, f.auth, None, vec![7])).await.into_parts();
        assert_eq!(refused.err(), Some(CoordinatedSlotError::Slot(CredentialSlotError::RevisionMismatch)));
        let counts = f.anchor.counts();
        let (owner, refused) = done(&cx, owner.replace(&cx, f.auth, Some(revision), vec![0; LIMIT + 1])).await.into_parts();
        assert_eq!(refused.err(), Some(CoordinatedSlotError::Slot(CredentialSlotError::Storage(AtomicFileError::TooLarge))));
        assert_eq!(f.anchor.counts(), counts, "oversized preflight cannot call the anchor");
        assert!(!owner.requires_recovery());
        assert_eq!(owner.revision(), Some(revision));
        assert_eq!(f.directory.contents(), bytes);
        assert_eq!(f.anchor.snapshot(), snapshot);
        done(&cx, owner.close(&cx)).await;
    });
}

#[test]
fn async_slot_interrupted_wait_retains_file_lock_and_does_not_block_siblings() {
    run(true, |cx| async move {
        let f = Fixture::new();
        let owner = f.open(&cx).await;
        let release = f.anchor.arm(Pause::Read);
        let before = f.anchor.counts();
        let mut pending = owner.load(&cx, f.auth).unwrap();
        release.0.wait_entered(&cx).await;
        let mut wait = Box::pin(pending.wait(&cx));
        poll_fn(|context| { assert!(wait.as_mut().poll(context).is_pending()); Poll::Ready(()) }).await;
        drop(wait);
        // Progress requires the runtime poller to remain free while the anchor
        // waits on a blocking worker. This is not a timing-only assertion.
        let mut sibling = cx.spawn(|sibling| async move { sibling.checkpoint().unwrap(); 42 }).unwrap();
        assert_eq!(sibling.join(&cx).await.unwrap(), 42);
        let refused = done(&cx, f.start_open(&cx)).await;
        assert!(matches!(refused, Err(CoordinatedSlotError::Slot(CredentialSlotError::Storage(AtomicFileError::Busy)))));
        release.0.release();
        let (owner, loaded) = pending.wait(&cx).await.unwrap().into_parts();
        assert_eq!(loaded.unwrap(), None);
        assert_eq!(f.anchor.counts(), (before.0 + 1, before.1));
        assert!(matches!(pending.wait(&cx).await, Err(CredentialIoError::AlreadyReceived)));
        done(&cx, owner.close(&cx)).await;
    });
}

#[test]
fn async_slot_no_pool_refuses_before_file_or_anchor_effects() {
    run(false, |cx| async move {
        let f = Fixture::new();
        assert!(matches!(f.start_open(&cx), Err(CredentialIoError::BlockingPoolUnavailable)));
        assert_eq!(f.anchor.counts(), (0, 0));
        assert_eq!(f.directory.contents(), None);
        assert_eq!(fs::read_dir(&f.directory.0).unwrap().count(), 0);
        assert_eq!(f.lane.snapshot().unwrap(), CredentialIoSnapshot::default());
    });
}

#[test]
fn async_slot_precommit_cancel_preserves_pending_intent_for_explicit_recovery() {
    run(true, |cx| async move {
        let f = Fixture::new();
        let owner = f.open(&cx).await;
        let release = f.anchor.arm(Pause::Prepared);
        let mut pending = owner.replace(&cx, f.auth, None, PAYLOAD.to_vec()).unwrap();
        release.0.wait_entered(&cx).await;
        pending.request_cancel().unwrap();
        release.0.release();
        let (owner, outcome) = pending.wait(&cx).await.unwrap().into_parts();
        assert!(outcome.is_err());
        assert!(owner.requires_recovery());
        assert_eq!(f.directory.contents(), None);
        assert!(matches!(f.anchor.snapshot().state(), CredentialAnchorState::Pending(_)));
        done(&cx, owner.close(&cx)).await;
        let (owner, recovery) = done(&cx, f.start_open(&cx)).await.unwrap();
        assert_eq!(recovery, Some(SlotRecoveryOutcome::NotCommitted(None)));
        assert!(!owner.requires_recovery());
        let (owner, outcome) = done(&cx, owner.replace(&cx, f.auth, None, PAYLOAD.to_vec())).await.into_parts();
        assert_eq!(outcome.unwrap().generation(), 1);
        done(&cx, owner.close(&cx)).await;
    });
}

#[test]
fn async_slot_postcommit_cancel_preserves_exact_disposition_but_not_take_payload() {
    run(true, |cx| async move {
        let f = Fixture::new();
        let owner = f.open(&cx).await;
        let (owner, outcome) = done(&cx, owner.replace(&cx, f.auth, None, PAYLOAD.to_vec())).await.into_parts();
        let revision = outcome.unwrap();
        let release = f.anchor.arm(Pause::Settled);
        let mut pending = owner.take(&cx, f.auth, revision).unwrap();
        release.0.wait_entered(&cx).await;
        let CredentialAnchorState::Stable(Some(committed)) = f.anchor.snapshot().state() else { panic!("anchor settled before cancellation"); };
        assert_eq!(committed.generation(), 2);
        pending.request_cancel().unwrap();
        release.0.release();
        let (owner, outcome) = pending.wait(&cx).await.unwrap().into_parts();
        assert_eq!(outcome.err(), Some(CoordinatedSlotError::CommittedWithoutDelivery(committed)));
        assert_eq!(owner.revision(), Some(committed));
        assert!(!owner.requires_recovery());
        let (owner, loaded) = done(&cx, owner.load(&cx, f.auth)).await.into_parts();
        assert_eq!(loaded.unwrap(), None);
        assert_eq!(f.anchor.counts().1, 4, "cancellation cannot repeat the tombstone transaction");
        done(&cx, owner.close(&cx)).await;
    });
}

#[test]
fn async_slot_uncertain_anchor_response_never_causes_an_automatic_retry() {
    run(true, |cx| async move {
        let f = Fixture::new();
        let owner = f.open(&cx).await;
        f.anchor.0.lock().unwrap().uncertain_prepare = true;
        let (owner, outcome) = done(&cx, owner.replace(&cx, f.auth, None, PAYLOAD.to_vec())).await.into_parts();
        assert_eq!(outcome.err(), Some(CoordinatedSlotError::Anchor(CredentialAnchorError::Uncertain)));
        assert!(owner.requires_recovery());
        let counts = f.anchor.counts();
        assert_eq!(counts.1, 1);
        let (owner, refused) = done(&cx, owner.load(&cx, f.auth)).await.into_parts();
        assert_eq!(refused.err(), Some(CoordinatedSlotError::RecoveryRequired));
        assert_eq!(f.anchor.counts(), counts);
        assert_eq!(f.directory.contents(), None);
        done(&cx, owner.close(&cx)).await;
        let (owner, recovery) = done(&cx, f.start_open(&cx)).await.unwrap();
        assert_eq!(recovery, Some(SlotRecoveryOutcome::NotCommitted(None)));
        assert_eq!(f.anchor.counts().1, 2);
        done(&cx, owner.close(&cx)).await;
    });
}

#[test]
fn async_slot_invalidation_is_durable_and_repeat_does_not_advance_tombstone() {
    run(true, |cx| async move {
        let f = Fixture::new();
        let owner = f.open(&cx).await;
        let (owner, outcome) = done(&cx, owner.invalidate(&cx, f.auth)).await.into_parts();
        let first = outcome.unwrap();
        assert_eq!(first.generation(), 1);
        let bytes = f.directory.contents();
        let snapshot = f.anchor.snapshot();
        let (owner, outcome) = done(&cx, owner.invalidate(&cx, f.auth)).await.into_parts();
        assert_eq!(outcome.unwrap(), first);
        assert_eq!(f.directory.contents(), bytes);
        assert_eq!(f.anchor.snapshot(), snapshot);
        done(&cx, owner.close(&cx)).await;
        let owner = f.open(&cx).await;
        assert_eq!(owner.revision(), Some(first));
        let (owner, loaded) = done(&cx, owner.load(&cx, f.auth)).await.into_parts();
        assert_eq!(loaded.unwrap(), None);
        done(&cx, owner.close(&cx)).await;
    });
}

#[test]
fn async_slot_shared_owner_cap_refuses_before_open_and_returns_after_close() {
    run(true, |cx| async move {
        let lane = CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(),
            CredentialIoLimits::new(1, 2, 1024 * 1024).unwrap()).unwrap();
        let first = Fixture::on_lane(lane.clone());
        let second = Fixture::on_lane(lane.clone());
        let owner = first.open(&cx).await;
        assert_eq!(lane.snapshot().unwrap().slots, 1);
        assert!(matches!(second.start_open(&cx), Err(CredentialIoError::CapacityExceeded)));
        assert_eq!(second.anchor.counts(), (0, 0));
        assert_eq!(fs::read_dir(&second.directory.0).unwrap().count(), 0);
        done(&cx, owner.close(&cx)).await;
        wait_jobs(&cx, &lane).await;
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
        let owner = second.open(&cx).await;
        assert_eq!(second.anchor.counts(), (1, 0));
        done(&cx, owner.close(&cx)).await;
        wait_jobs(&cx, &lane).await;
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
    });
}

#[test]
fn async_slot_count_and_byte_saturation_leave_the_other_store_untouched() {
    run(true, |cx| async move {
        for byte_limited in [false, true] {
            let lane = CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(),
                CredentialIoLimits::new(4, if byte_limited { 2 } else { 1 },
                    if byte_limited { 16 * 1024 + 8 * LIMIT } else { 1024 * 1024 }).unwrap()).unwrap();
            let first = Fixture::on_lane(lane.clone());
            let second = Fixture::on_lane(lane.clone());
            let owner = first.open(&cx).await;
            let release = first.anchor.arm(Pause::Read);
            let mut pending = owner.load(&cx, first.auth).unwrap();
            release.0.wait_entered(&cx).await;
            let before = lane.snapshot().unwrap();
            assert_eq!(before.operations, 1);
            assert!(matches!(second.start_open(&cx), Err(CredentialIoError::CapacityExceeded)));
            assert_eq!(lane.snapshot().unwrap(), before, "failed admission cannot leak its reserved slot");
            assert_eq!(second.anchor.counts(), (0, 0));
            assert_eq!(fs::read_dir(&second.directory.0).unwrap().count(), 0);
            release.0.release();
            let (owner, loaded) = pending.wait(&cx).await.unwrap().into_parts();
            assert_eq!(loaded.unwrap(), None);
            wait_jobs(&cx, &lane).await;
            let other = second.open(&cx).await;
            done(&cx, other.close(&cx)).await;
            done(&cx, owner.close(&cx)).await;
            wait_jobs(&cx, &lane).await;
            assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
        }
    });
}

#[test]
fn async_slot_dropped_operation_retains_capacity_until_provider_releases() {
    run(true, |cx| async move {
        let lane = CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(),
            CredentialIoLimits::new(1, 1, 1024 * 1024).unwrap()).unwrap();
        let f = Fixture::on_lane(lane.clone());
        let owner = f.open(&cx).await;
        let release = f.anchor.arm(Pause::Read);
        let pending = owner.load(&cx, f.auth).unwrap();
        release.0.wait_entered(&cx).await;
        let before = lane.snapshot().unwrap();
        drop(pending);
        assert_eq!(lane.snapshot().unwrap(), before, "dropping a task does not stop a running anchor call");
        assert!(matches!(f.start_open(&cx), Err(CredentialIoError::CapacityExceeded)));
        release.0.release();
        wait_jobs(&cx, &lane).await;
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
        let owner = f.open(&cx).await;
        done(&cx, owner.close(&cx)).await;
        wait_jobs(&cx, &lane).await;
    });
}

#[test]
fn async_slot_close_remains_available_during_data_saturation() {
    run(true, |cx| async move {
        let lane = CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(),
            CredentialIoLimits::new(2, 1, 1024 * 1024).unwrap()).unwrap();
        let first = Fixture::on_lane(lane.clone());
        let second = Fixture::on_lane(lane.clone());
        let owner = first.open(&cx).await;
        let other = second.open(&cx).await;
        let release = first.anchor.arm(Pause::Read);
        let mut pending = owner.load(&cx, first.auth).unwrap();
        release.0.wait_entered(&cx).await;
        assert_eq!(lane.snapshot().unwrap().operations, 1);
        done(&cx, other.close(&cx)).await;
        assert_eq!(lane.snapshot().unwrap().slots, 1, "close releases a file owner despite a full data queue");
        assert_eq!(lane.snapshot().unwrap().operations, 1);
        release.0.release();
        let (owner, loaded) = pending.wait(&cx).await.unwrap().into_parts();
        assert_eq!(loaded.unwrap(), None);
        done(&cx, owner.close(&cx)).await;
        wait_jobs(&cx, &lane).await;
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
    });
}
