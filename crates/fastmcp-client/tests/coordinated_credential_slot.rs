#![cfg(target_os = "linux")]

//! Real data-file and anchor-file transaction tests. The test-only anchor lives
//! in a separately retained directory and injects provider acknowledgement
//! failures. This does not qualify an external anchor service, independent
//! backup administration, encryption, kernel power loss, or OAuth end to end.

use std::fs::{self, DirBuilder, File};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use fastmcp_client::http_auth::secure_file::{AtomicFileVersion, SecureAtomicFile};
use fastmcp_client::http_auth::secure_file::slot::{
    CredentialSlotError, SlotCommitIntent, SlotRevision, SLOT_INTENT_BYTES, SLOT_REVISION_BYTES,
};
use fastmcp_client::http_auth::secure_file::slot::coordinator::{
    CoordinatedCredentialSlot, CoordinatedSlotError, CredentialAnchorBinding,
    CredentialAnchorError, CredentialAnchorSnapshot, CredentialAnchorState, CredentialCommitAnchor,
};
use fastmcp_core::partition::{
    CredentialStoreKey, DurableOwnerKey, PartitionAuthorization, PartitionDescriptor,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
const NAMESPACE: &str = "deployment:credential-store";

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        for _ in 0..128 {
            let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("fastmcp-coordinator-{}-{id}", std::process::id()));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("private fixture directory: {error}"),
            }
        }
        panic!("fixture directory collision bound exceeded");
    }

    fn file(&self, cx: &Cx, name: &str) -> SecureAtomicFile {
        SecureAtomicFile::open(cx, File::open(&self.0).unwrap(), name, 4096).unwrap()
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        // Only the temporary directory actually created by this test is removed.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn identity(subject: &str) -> (CredentialStoreKey, PartitionAuthorization) {
    let descriptor = PartitionDescriptor::from_verified_facts(
        "fixture-provider", 1, "https://issuer.example", "https://resource.example/mcp",
        "fixture-tenant", subject, "native-client", 1, 1, &[b"fixture-audience"],
    ).unwrap();
    let owner = DurableOwnerKey::derive(&descriptor, 1).unwrap();
    (
        CredentialStoreKey::derive(&descriptor, "fixture-store", "refresh-family", "stable-lineage").unwrap(),
        PartitionAuthorization::current(&descriptor, &owner),
    )
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Fault {
    BeforePrepare,
    AfterPrepare,
    BeforeSettle,
    AfterSettle,
    CancelAfterPrepare,
    CancelAfterSettle,
    WrongPrepareSequence,
    WrongPrepareState,
    ReadUnavailable,
}

#[derive(Default)]
struct Observations {
    fault: Option<Fault>,
    reads: usize,
    transitions: Vec<CredentialAnchorState>,
}

type Control = Arc<Mutex<Observations>>;

/// A test provider backed by actual SecureAtomicFile writes. Provisioning is
/// explicit; current() never invents a missing entry. Faults are injected only
/// at the acknowledgement boundaries, not as substitutes for disk operations.
struct FileAnchor {
    file: SecureAtomicFile,
    binding: CredentialAnchorBinding,
    control: Control,
}

impl FileAnchor {
    fn new(directory: &Directory, cx: &Cx, binding: CredentialAnchorBinding, control: Control) -> Self {
        Self { file: directory.file(cx, "anchor"), binding, control }
    }

    fn provision(&mut self, cx: &Cx, sequence: u64) {
        let snapshot = CredentialAnchorSnapshot::new(self.binding, sequence, CredentialAnchorState::Stable(None));
        self.file.replace(cx, None, &encode(snapshot)).unwrap();
    }

    fn read(&self, cx: &Cx) -> Result<(CredentialAnchorSnapshot, AtomicFileVersion), CredentialAnchorError> {
        let raw = self.file.load(cx).map_err(|_| CredentialAnchorError::Unavailable)?
            .ok_or(CredentialAnchorError::NotProvisioned)?;
        let bytes = raw.bytes();
        if bytes.len() < 41 || &bytes[..32] != self.binding.as_bytes() {
            return Err(CredentialAnchorError::Conflict);
        }
        let sequence = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
        let state = match bytes[40] {
            0 if bytes.len() == 41 => CredentialAnchorState::Stable(None),
            1 if bytes.len() == 41 + SLOT_REVISION_BYTES => CredentialAnchorState::Stable(Some(
                SlotRevision::from_trusted_bytes(&bytes[41..]).map_err(|_| CredentialAnchorError::Conflict)?,
            )),
            2 if bytes.len() == 41 + SLOT_INTENT_BYTES => CredentialAnchorState::Pending(
                SlotCommitIntent::from_trusted_bytes(&bytes[41..]).map_err(|_| CredentialAnchorError::Conflict)?,
            ),
            _ => return Err(CredentialAnchorError::Conflict),
        };
        Ok((CredentialAnchorSnapshot::new(self.binding, sequence, state), raw.version()))
    }
}

fn encode(snapshot: CredentialAnchorSnapshot) -> Vec<u8> {
    let mut bytes = snapshot.binding().as_bytes().to_vec();
    bytes.extend_from_slice(&snapshot.sequence().to_be_bytes());
    match snapshot.state() {
        CredentialAnchorState::Stable(None) => bytes.push(0),
        CredentialAnchorState::Stable(Some(revision)) => {
            bytes.push(1);
            bytes.extend_from_slice(&revision.to_bytes());
        }
        CredentialAnchorState::Pending(intent) => {
            bytes.push(2);
            bytes.extend_from_slice(&intent.to_bytes());
        }
    }
    bytes
}

impl CredentialCommitAnchor for FileAnchor {
    fn current(&mut self, cx: &Cx, binding: &CredentialAnchorBinding) -> Result<CredentialAnchorSnapshot, CredentialAnchorError> {
        let mut control = self.control.lock().unwrap();
        control.reads += 1;
        if control.fault == Some(Fault::ReadUnavailable) {
            control.fault = None;
            return Err(CredentialAnchorError::Unavailable);
        }
        drop(control);
        if *binding != self.binding { return Err(CredentialAnchorError::Conflict); }
        Ok(self.read(cx)?.0)
    }

    fn compare_exchange(
        &mut self,
        cx: &Cx,
        expected: &CredentialAnchorSnapshot,
        next: CredentialAnchorState,
    ) -> Result<CredentialAnchorSnapshot, CredentialAnchorError> {
        let (actual, version) = self.read(cx)?;
        if actual != *expected { return Err(CredentialAnchorError::Conflict); }
        let preparing = matches!(next, CredentialAnchorState::Pending(_));
        let fault = {
            let mut control = self.control.lock().unwrap();
            control.transitions.push(next);
            let applies = matches!((preparing, control.fault),
                (true, Some(Fault::BeforePrepare | Fault::AfterPrepare | Fault::CancelAfterPrepare
                    | Fault::WrongPrepareSequence | Fault::WrongPrepareState))
                | (false, Some(Fault::BeforeSettle | Fault::AfterSettle | Fault::CancelAfterSettle))
            );
            if applies { control.fault.take() } else { None }
        };
        if matches!(fault, Some(Fault::BeforePrepare | Fault::BeforeSettle)) {
            return Err(CredentialAnchorError::Unavailable);
        }
        let sequence = actual.sequence().checked_add(1).ok_or(CredentialAnchorError::Conflict)?;
        let committed = CredentialAnchorSnapshot::new(self.binding, sequence, next);
        self.file.replace(cx, Some(version), &encode(committed))
            .map_err(|_| CredentialAnchorError::Uncertain)?;
        match fault {
            Some(Fault::AfterPrepare | Fault::AfterSettle) => Err(CredentialAnchorError::Uncertain),
            Some(Fault::CancelAfterPrepare | Fault::CancelAfterSettle) => {
                cx.set_cancel_requested(true);
                Ok(committed)
            }
            Some(Fault::WrongPrepareSequence) => Ok(CredentialAnchorSnapshot::new(self.binding, sequence + 1, next)),
            Some(Fault::WrongPrepareState) => Ok(CredentialAnchorSnapshot::new(self.binding, sequence, expected.state())),
            _ => Ok(committed),
        }
    }
}

struct Fixture {
    data: Directory,
    anchor: Directory,
    key: CredentialStoreKey,
    authorization: PartitionAuthorization,
    binding: CredentialAnchorBinding,
    control: Control,
}

impl Fixture {
    fn new() -> Self {
        let (key, authorization) = identity("alice");
        Self {
            data: Directory::new(), anchor: Directory::new(), key, authorization,
            binding: CredentialAnchorBinding::for_store(NAMESPACE, &key, &authorization).unwrap(),
            control: Arc::new(Mutex::new(Observations::default())),
        }
    }

    fn provision(&self, cx: &Cx, sequence: u64) {
        FileAnchor::new(&self.anchor, cx, self.binding, self.control.clone()).provision(cx, sequence);
    }

    fn open(&self, cx: &Cx) -> Result<(CoordinatedCredentialSlot<FileAnchor>, Option<fastmcp_client::http_auth::secure_file::slot::SlotRecoveryOutcome>), CoordinatedSlotError> {
        CoordinatedCredentialSlot::open(
            cx, self.data.file(cx, "credential"), &self.key, &self.authorization, NAMESPACE,
            FileAnchor::new(&self.anchor, cx, self.binding, self.control.clone()),
        )
    }

    fn fault(&self, fault: Fault) {
        self.control.lock().unwrap().fault = Some(fault);
    }

    fn data_bytes(&self) -> Vec<u8> { fs::read(self.data.0.join("credential")).unwrap() }
}

#[test]
fn replacement_and_take_settle_anchor_before_delivery_and_reopen() {
    let fixture = Fixture::new();
    let cx = Cx::for_testing();
    fixture.provision(&cx, 0);
    let (mut slot, recovery) = fixture.open(&cx).unwrap();
    assert!(recovery.is_none());
    let first = slot.replace(&cx, &fixture.authorization, None, b"protected-once").unwrap();
    assert_eq!(slot.load(&cx, &fixture.authorization).unwrap(), Some(b"protected-once".to_vec()));
    let take = slot.take(&cx, &fixture.authorization, first).unwrap();
    let tombstone = take.revision();
    assert_eq!(take.into_consumed(), Some(b"protected-once".to_vec()));
    assert!(!slot.requires_recovery());
    {
        let observed = fixture.control.lock().unwrap();
        let transitions = &observed.transitions;
        assert_eq!(transitions.len(), 4);
        assert!(matches!(transitions[0], CredentialAnchorState::Pending(_)));
        assert_eq!(transitions[1], CredentialAnchorState::Stable(Some(first)));
        assert!(matches!(transitions[2], CredentialAnchorState::Pending(_)));
        assert_eq!(transitions[3], CredentialAnchorState::Stable(Some(tombstone)));
    }
    drop(slot);
    let (mut reopened, recovery) = fixture.open(&cx).unwrap();
    assert!(recovery.is_none());
    assert_eq!(reopened.revision(), Some(tombstone));
    assert_eq!(reopened.load(&cx, &fixture.authorization).unwrap(), None);
    assert_eq!(reopened.take(&cx, &fixture.authorization, tombstone).err(), Some(CoordinatedSlotError::Slot(CredentialSlotError::Empty)));
}

#[test]
fn missing_anchor_is_not_implicitly_provisioned_from_an_empty_data_file() {
    let fixture = Fixture::new();
    let cx = Cx::for_testing();
    assert_eq!(fixture.open(&cx).err(), Some(CoordinatedSlotError::Anchor(CredentialAnchorError::NotProvisioned)));
    assert!(!fixture.data.0.join("credential").exists());
    assert!(!fixture.anchor.0.join("anchor").exists());
    fixture.provision(&cx, 0);
    assert!(fixture.open(&cx).is_ok());
}

#[test]
fn failure_before_prepare_writes_no_data_and_requires_explicit_reopen() {
    let fixture = Fixture::new();
    let cx = Cx::for_testing();
    fixture.provision(&cx, 0);
    let (mut slot, _) = fixture.open(&cx).unwrap();
    fixture.fault(Fault::BeforePrepare);
    assert_eq!(slot.replace(&cx, &fixture.authorization, None, b"never-written").err(), Some(CoordinatedSlotError::Anchor(CredentialAnchorError::Unavailable)));
    assert!(slot.requires_recovery());
    assert!(!fixture.data.0.join("credential").exists());
    assert_eq!(slot.load(&cx, &fixture.authorization).err(), Some(CoordinatedSlotError::RecoveryRequired));
    assert_eq!(fixture.control.lock().unwrap().transitions.len(), 1);
    drop(slot);
    let (mut slot, recovery) = fixture.open(&cx).unwrap();
    assert!(recovery.is_none());
    assert_eq!(slot.load(&cx, &fixture.authorization).unwrap(), None);
    slot.replace(&cx, &fixture.authorization, None, b"fresh-attempt").unwrap();
}

#[test]
fn lost_prepare_ack_recovers_old_state_without_inventing_a_data_commit() {
    let fixture = Fixture::new();
    let cx = Cx::for_testing();
    fixture.provision(&cx, 0);
    let (mut slot, _) = fixture.open(&cx).unwrap();
    fixture.fault(Fault::AfterPrepare);
    assert_eq!(slot.replace(&cx, &fixture.authorization, None, b"not-dispatched").err(), Some(CoordinatedSlotError::Anchor(CredentialAnchorError::Uncertain)));
    assert!(!fixture.data.0.join("credential").exists());
    assert!(slot.requires_recovery());
    drop(slot);
    let (mut slot, recovery) = fixture.open(&cx).unwrap();
    assert_eq!(recovery, Some(fastmcp_client::http_auth::secure_file::slot::SlotRecoveryOutcome::NotCommitted(None)));
    assert_eq!(slot.load(&cx, &fixture.authorization).unwrap(), None);
    slot.replace(&cx, &fixture.authorization, None, b"fresh").unwrap();
}

#[test]
fn lost_settlement_ack_never_redelivers_a_consumed_payload_after_reopen() {
    for fault in [Fault::BeforeSettle, Fault::AfterSettle] {
        let fixture = Fixture::new();
        let cx = Cx::for_testing();
        fixture.provision(&cx, 0);
        let (mut slot, _) = fixture.open(&cx).unwrap();
        let revision = slot.replace(&cx, &fixture.authorization, None, b"once").unwrap();
        fixture.fault(fault);
        assert!(slot.take(&cx, &fixture.authorization, revision).is_err());
        assert!(slot.requires_recovery());
        assert_eq!(slot.load(&cx, &fixture.authorization).err(), Some(CoordinatedSlotError::RecoveryRequired));
        drop(slot);
        let (mut slot, recovered) = fixture.open(&cx).unwrap();
        if fault == Fault::BeforeSettle { assert!(recovered.is_some()); }
        else { assert!(recovered.is_none()); }
        assert_eq!(slot.load(&cx, &fixture.authorization).unwrap(), None);
        assert_eq!(slot.revision().unwrap().generation(), 2);
        assert_eq!(slot.take(&cx, &fixture.authorization, slot.revision().unwrap()).err(), Some(CoordinatedSlotError::Slot(CredentialSlotError::Empty)));
    }
}

#[test]
fn malformed_provider_ack_prevents_data_mutation_and_is_not_retried() {
    for fault in [Fault::WrongPrepareSequence, Fault::WrongPrepareState] {
        let fixture = Fixture::new();
        let cx = Cx::for_testing();
        fixture.provision(&cx, 0);
        let (mut slot, _) = fixture.open(&cx).unwrap();
        fixture.fault(fault);
        assert_eq!(slot.replace(&cx, &fixture.authorization, None, b"must-not-write").err(), Some(CoordinatedSlotError::InvalidAnchorResponse));
        assert!(!fixture.data.0.join("credential").exists());
        assert_eq!(fixture.control.lock().unwrap().transitions.len(), 1);
        assert!(slot.requires_recovery());
        drop(slot);
        let (mut slot, recovery) = fixture.open(&cx).unwrap();
        assert!(recovery.is_some());
        assert_eq!(slot.load(&cx, &fixture.authorization).unwrap(), None);
    }
}

#[test]
fn cancellation_after_prepare_keeps_old_data_and_reconciles_the_pending_intent() {
    let fixture = Fixture::new();
    let cx = Cx::for_testing();
    fixture.provision(&cx, 0);
    let (mut slot, _) = fixture.open(&cx).unwrap();
    let revision = slot.replace(&cx, &fixture.authorization, None, b"retained").unwrap();
    let old = fixture.data_bytes();
    fixture.fault(Fault::CancelAfterPrepare);
    assert!(slot.take(&cx, &fixture.authorization, revision).is_err());
    assert!(cx.is_cancel_requested());
    assert_eq!(fixture.data_bytes(), old);
    assert!(slot.requires_recovery());
    drop(slot);
    let live = Cx::for_testing();
    let (mut slot, recovery) = fixture.open(&live).unwrap();
    assert!(recovery.is_some());
    assert_eq!(slot.revision(), Some(revision));
    assert_eq!(slot.load(&live, &fixture.authorization).unwrap(), Some(b"retained".to_vec()));
}

#[test]
fn cancellation_after_full_commit_reports_settled_revision_but_releases_no_handoff() {
    let fixture = Fixture::new();
    let cx = Cx::for_testing();
    fixture.provision(&cx, 0);
    let (mut slot, _) = fixture.open(&cx).unwrap();
    let revision = slot.replace(&cx, &fixture.authorization, None, b"once").unwrap();
    fixture.fault(Fault::CancelAfterSettle);
    let error = slot.take(&cx, &fixture.authorization, revision).err().unwrap();
    assert_eq!(error, CoordinatedSlotError::CommittedWithoutDelivery(slot.revision().unwrap()));
    assert!(!slot.requires_recovery());
    let live = Cx::for_testing();
    assert_eq!(slot.load(&live, &fixture.authorization).unwrap(), None);
    drop(slot);
    let (mut slot, recovery) = fixture.open(&live).unwrap();
    assert!(recovery.is_none());
    assert_eq!(slot.load(&live, &fixture.authorization).unwrap(), None);
}

#[test]
fn stale_revision_and_size_refusals_do_not_prepare_anchor_mutations() {
    let fixture = Fixture::new();
    let cx = Cx::for_testing();
    fixture.provision(&cx, 0);
    let (mut slot, _) = fixture.open(&cx).unwrap();
    let revision = slot.replace(&cx, &fixture.authorization, None, b"winner").unwrap();
    let calls = fixture.control.lock().unwrap().transitions.len();
    assert_eq!(slot.replace(&cx, &fixture.authorization, None, b"stale").err(), Some(CoordinatedSlotError::Slot(CredentialSlotError::RevisionMismatch)));
    let excessive = vec![0; slot.maximum_payload_bytes() + 1];
    assert!(slot.replace(&cx, &fixture.authorization, Some(revision), &excessive).is_err());
    assert_eq!(fixture.control.lock().unwrap().transitions.len(), calls);
    assert_eq!(slot.load(&cx, &fixture.authorization).unwrap(), Some(b"winner".to_vec()));
}

#[test]
fn unauthorized_caller_does_not_even_query_the_owners_anchor() {
    let fixture = Fixture::new();
    let cx = Cx::for_testing();
    fixture.provision(&cx, 0);
    let (mut slot, _) = fixture.open(&cx).unwrap();
    let revision = slot.replace(&cx, &fixture.authorization, None, b"alice").unwrap();
    let (_, bob) = identity("bob");
    let reads = fixture.control.lock().unwrap().reads;
    assert_eq!(slot.load(&cx, &bob).err(), Some(CoordinatedSlotError::Slot(CredentialSlotError::BindingMismatch)));
    assert!(slot.take(&cx, &bob, revision).is_err());
    assert_eq!(fixture.control.lock().unwrap().reads, reads);
    assert!(!slot.requires_recovery());
    assert_eq!(slot.load(&cx, &fixture.authorization).unwrap(), Some(b"alice".to_vec()));
}

#[test]
fn coherent_data_rollback_is_rejected_against_the_independent_settled_anchor() {
    let fixture = Fixture::new();
    let cx = Cx::for_testing();
    fixture.provision(&cx, 0);
    let (mut slot, _) = fixture.open(&cx).unwrap();
    let first = slot.replace(&cx, &fixture.authorization, None, b"old").unwrap();
    let backup = fixture.data_bytes();
    let current = slot.replace(&cx, &fixture.authorization, Some(first), b"new").unwrap();
    drop(slot);
    let anchor_before = fs::read(fixture.anchor.0.join("anchor")).unwrap();
    fs::write(fixture.data.0.join("credential"), &backup).unwrap();
    assert_eq!(fixture.open(&cx).err(), Some(CoordinatedSlotError::Slot(CredentialSlotError::RevisionMismatch)));
    assert_eq!(fixture.data_bytes(), backup);
    assert_eq!(fs::read(fixture.anchor.0.join("anchor")).unwrap(), anchor_before);
    assert_eq!(current.generation(), 2);
}

#[test]
fn sequence_capacity_reserves_both_prepare_and_settlement_before_mutation() {
    let fixture = Fixture::new();
    let cx = Cx::for_testing();
    fixture.provision(&cx, u64::MAX - 1);
    let (mut slot, _) = fixture.open(&cx).unwrap();
    assert_eq!(slot.replace(&cx, &fixture.authorization, None, b"never").err(), Some(CoordinatedSlotError::SequenceExhausted));
    assert_eq!(fixture.control.lock().unwrap().transitions.len(), 0);
    assert!(!fixture.data.0.join("credential").exists());
    assert!(!slot.requires_recovery());
}

#[test]
fn anchor_outage_stops_reads_without_silently_using_cached_authority() {
    let fixture = Fixture::new();
    let cx = Cx::for_testing();
    fixture.provision(&cx, 0);
    let (mut slot, _) = fixture.open(&cx).unwrap();
    slot.replace(&cx, &fixture.authorization, None, b"private").unwrap();
    fixture.fault(Fault::ReadUnavailable);
    assert_eq!(slot.load(&cx, &fixture.authorization).err(), Some(CoordinatedSlotError::Anchor(CredentialAnchorError::Unavailable)));
    assert!(slot.requires_recovery());
    assert_eq!(slot.load(&cx, &fixture.authorization).err(), Some(CoordinatedSlotError::RecoveryRequired));
    drop(slot);
    let (mut slot, _) = fixture.open(&cx).unwrap();
    assert_eq!(slot.load(&cx, &fixture.authorization).unwrap(), Some(b"private".to_vec()));
}

#[test]
fn namespace_binding_is_injective_and_invalid_names_fail_before_provider_access() {
    let fixture = Fixture::new();
    let same = CredentialAnchorBinding::for_store(NAMESPACE, &fixture.key, &fixture.authorization).unwrap();
    assert_eq!(same, fixture.binding);
    let other = CredentialAnchorBinding::for_store("deployment:other", &fixture.key, &fixture.authorization).unwrap();
    assert_ne!(same, other);
    for namespace in ["", "bad/namespace", "bad\nnamespace", "é"] {
        assert_eq!(CredentialAnchorBinding::for_store(namespace, &fixture.key, &fixture.authorization).err(), Some(CoordinatedSlotError::InvalidNamespace));
    }
    assert_eq!(CredentialAnchorBinding::for_store(&"x".repeat(129), &fixture.key, &fixture.authorization).err(), Some(CoordinatedSlotError::InvalidNamespace));
    assert!(CredentialAnchorBinding::for_store(&"x".repeat(128), &fixture.key, &fixture.authorization).is_ok());
    assert_eq!(fixture.control.lock().unwrap().reads, 0);
}
