//! Protected, synchronized file storage for one Task's input-update journal.
//!
//! This adapter performs real conditional file replacement and reopen/reconcile
//! work. All methods are blocking: call them from the host's owned blocking
//! lane and bridge that lane with TaskInputJournalPersistence. No runtime,
//! worker, encryption key or permissive persistence sink is installed here.
//! The existing protector contract remains a host qualification obligation.

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::{McpRequestCancellation, runtime::ProcessBoundToken};
use crate::http_auth::secure_file::{AtomicFileError, AtomicFileSnapshot, AtomicFileVersion, SecureAtomicFile};
use super::super::super::checkpoint::resume::{TaskResumeBinding, store::TaskResumeProtector};
use super::{TaskId, TaskInputJournalChange, TaskInputJournalError, TaskInputJournalRecord,
    MAX_INPUT_JOURNAL_BYTES, associated_data, check};

/// One exclusive file under verified host custody. Neither stale callers nor
/// restarted drivers can clear an uncertain remote update or reset its budget.
/// There is intentionally no prune, delete, truncate, or overwrite-unconditionally
/// API. External deletion/rollback must be prevented by the deployment.
pub struct FileTaskInputJournal<P> {
    file: SecureAtomicFile,
    process: ProcessBoundToken,
    protector: P,
    binding: TaskResumeBinding,
    record: TaskInputJournalRecord,
    revision: Option<AtomicFileVersion>,
    uncertain: Option<(Option<AtomicFileVersion>, AtomicFileVersion)>,
}
impl<P: TaskResumeProtector> FileTaskInputJournal<P> {
    pub fn open(cx: &Cx, process: ProcessBoundToken, file: SecureAtomicFile,
        mut protector: P, binding: TaskResumeBinding, task: TaskId,
    ) -> Result<Self, TaskInputJournalError> {
        process.verify().map_err(|_| TaskInputJournalError::BindingMismatch)?;
        context(cx)?;
        if protector.profile() != *binding.protection_profile()
            || file.maximum_bytes() > MAX_INPUT_JOURNAL_BYTES
        { return Err(TaskInputJournalError::BindingMismatch); }
        let snapshot = file.load(cx).map_err(|_| TaskInputJournalError::Persistence)?;
        let (revision, record) = decode(cx, &mut protector, &binding, &task, snapshot)?;
        context(cx)?;
        Ok(Self { file, process, protector, binding, record, revision, uncertain: None })
    }

    fn admit(&self, cx: &Cx, current: &TaskResumeBinding) -> Result<(), TaskInputJournalError> {
        context(cx)?;
        self.process.verify().map_err(|_| TaskInputJournalError::BindingMismatch)?;
        if self.binding.associated_data() != current.associated_data()
            || self.protector.profile() != *current.protection_profile()
        { return Err(TaskInputJournalError::BindingMismatch); }
        Ok(())
    }

    /// Restore only this authenticated snapshot, not a cached predecessor from
    /// a failed save. An uncertain file commit must first be reconciled below.
    pub fn record(&self, cx: &Cx, current: &TaskResumeBinding) -> Result<TaskInputJournalRecord, TaskInputJournalError> {
        self.admit(cx, current)?;
        if self.uncertain.is_some() { return Err(TaskInputJournalError::ReconciliationRequired); }
        Ok(self.record.clone())
    }

    /// Persist exactly one driver-proposed successor. The complete predecessor
    /// AND the underlying file version must match. Success follows file and
    /// directory synchronization; a late cancellation cannot erase that receipt.
    pub fn apply(&mut self, cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time,
        current: &TaskResumeBinding, change: TaskInputJournalChange,
    ) -> Result<TaskInputJournalRecord, TaskInputJournalError> {
        check(cx, cancellation, deadline)?;
        self.admit(cx, current)?;
        if self.uncertain.is_some() { return Err(TaskInputJournalError::ReconciliationRequired); }
        if change.expected != self.record { return Err(TaskInputJournalError::InvalidReceipt); }
        if change.proposed.binding != self.record.binding || change.proposed.task_id != self.record.task_id
            || change.proposed.generation != self.record.generation.checked_add(1).ok_or(TaskInputJournalError::Capacity)?
        { return Err(TaskInputJournalError::InvalidRecord); }
        let plaintext = change.proposed.encode()?;
        let ciphertext = self.protector.seal(cx, &self.record.binding, &plaintext, self.file.maximum_bytes())
            .map_err(|_| TaskInputJournalError::Persistence)?;
        if ciphertext.is_empty() || ciphertext.len() > self.file.maximum_bytes() {
            return Err(TaskInputJournalError::Capacity);
        }
        check(cx, cancellation, deadline)?;
        let revision = match self.file.replace(cx, self.revision, &ciphertext) {
            Ok(revision) => revision,
            Err(AtomicFileError::CommitUncertain { attempted }) => {
                self.uncertain = Some((self.revision, attempted));
                return Err(TaskInputJournalError::ReconciliationRequired);
            }
            Err(_) => return Err(TaskInputJournalError::Persistence),
        };
        self.revision = Some(revision);
        self.record = change.proposed;
        Ok(self.record.clone())
    }

    /// Reconcile only the exact old/attempted ciphertext identities. This never
    /// repeats a write or contacts the remote Task. If the stored intent won,
    /// the reopened journal remains Unconfirmed and input mutation stays blocked.
    pub fn reconcile(&mut self, cx: &Cx, current: &TaskResumeBinding) -> Result<(), TaskInputJournalError> {
        self.admit(cx, current)?;
        let Some((previous, attempted)) = self.uncertain else { return Ok(()); };
        let snapshot = self.file.reconcile(cx).map_err(|_| TaskInputJournalError::Persistence)?;
        let observed = snapshot.as_ref().map(AtomicFileSnapshot::version);
        if observed != previous && observed != Some(attempted) {
            return Err(TaskInputJournalError::ReconciliationRequired);
        }
        let (revision, record) = decode(cx, &mut self.protector, current, &self.record.task_id, snapshot)?;
        context(cx)?;
        self.revision = revision;
        self.record = record;
        self.uncertain = None;
        Ok(())
    }
}

fn context(cx: &Cx) -> Result<(), TaskInputJournalError> {
    cx.checkpoint().map_err(|_| TaskInputJournalError::Cancelled)?;
    if cx.budget().deadline.is_some_and(|deadline| cx.now() >= deadline) {
        return Err(TaskInputJournalError::TimedOut);
    }
    Ok(())
}

fn decode<P: TaskResumeProtector>(cx: &Cx, protector: &mut P, binding: &TaskResumeBinding,
    task: &TaskId, snapshot: Option<AtomicFileSnapshot>,
) -> Result<(Option<AtomicFileVersion>, TaskInputJournalRecord), TaskInputJournalError> {
    let Some(snapshot) = snapshot else { return Ok((None, TaskInputJournalRecord::empty(binding, task.clone())?)); };
    if snapshot.bytes().is_empty() { return Err(TaskInputJournalError::InvalidRecord); }
    let aad = associated_data(binding, task)?;
    let plaintext = protector.open(cx, &aad, snapshot.bytes(), MAX_INPUT_JOURNAL_BYTES)
        .map_err(|_| TaskInputJournalError::Persistence)?;
    let record = TaskInputJournalRecord::decode(&plaintext)?;
    if record.binding != aad || &record.task_id != task { return Err(TaskInputJournalError::BindingMismatch); }
    // Empty is represented by authoritative physical absence only. Accepting an
    // encrypted reset record would erase all prior attempt evidence on reopen.
    if record.generation == 0 { return Err(TaskInputJournalError::InvalidRecord); }
    Ok((Some(snapshot.version()), record))
}
