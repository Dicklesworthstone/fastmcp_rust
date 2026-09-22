//! Write-ahead input-update controls for an explicitly journaled Task driver.
//!
//! The complete intent must be durably acknowledged BEFORE an update can be
//! sent. A second write records the admitted remote ACK. Restoring an intent
//! without that receipt permits observation, never another input mutation.
//! Acknowledged input keys and lifetime budgets survive ordinary restarts.
//!
//! Records contain identities and descriptor digests, never input answers,
//! descriptors, bearer tokens or tool payloads. Encoding is NOT protection:
//! restore only bytes authenticated by the host's configured durable provider.
//! The host must supply the CURRENT verified owner binding, retain exclusive
//! storage custody, and prevent deletion/rollback of committed controls. This
//! is not an independent anti-rollback anchor or exactly-once execution proof.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation, sha256_bounded};
use fastmcp_protocol::RequestId;
use fastmcp_protocol::tasks_extension::{Task, TaskId, TaskTimestamp};

use super::{InputHistory, ManagedTaskWatchDrivePolicy, TaskInputUpdateState};
use super::super::checkpoint::resume::TaskResumeBinding;

/// Synchronized Linux file storage; blocking work belongs to the caller's lane.
#[cfg(target_os = "linux")]
pub mod file;

const MAGIC: &[u8; 8] = b"FMTIJ001";
const MAX_KEYS: usize = 4096;
const MAX_UPDATES: usize = 128;
/// Bounds one complete plaintext record, including identifiers and framing.
pub const MAX_INPUT_JOURNAL_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskInputJournalError {
    InvalidRecord,
    BindingMismatch,
    TaskChanged,
    Capacity,
    IdentityReused,
    ReconciliationRequired,
    Persistence,
    InvalidReceipt,
    Cancelled,
    TimedOut,
}
impl fmt::Display for TaskInputJournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRecord => "invalid Task input journal",
            Self::BindingMismatch => "Task input journal binding differs from current authority",
            Self::TaskChanged => "Task input journal identity changed",
            Self::Capacity => "Task input journal capacity exhausted",
            Self::IdentityReused => "Task input journal request identity was already used",
            Self::ReconciliationRequired => "Task input update requires explicit reconciliation; mutation withheld",
            Self::Persistence => "Task input journal persistence failed",
            Self::InvalidReceipt => "Task input journal persistence returned a different record",
            Self::Cancelled => "Task input journal operation cancelled",
            Self::TimedOut => "Task input journal deadline expired",
        })
    }
}
impl std::error::Error for TaskInputJournalError {}

/// A fixed-schema control record. No arbitrary application JSON is retained.
/// Unconfirmed is deliberately conservative: intent persistence may precede a
/// network attempt that never occurs. Absence of a receipt is NOT retry authority.
#[derive(Clone)]
pub struct TaskInputJournalRecord {
    binding: [u8; 32],
    task_id: TaskId,
    created_at: Option<String>,
    history: InputHistory,
    ids: BTreeSet<String>,
    last_id: Option<String>,
    pending_keys: BTreeSet<String>,
    acknowledged: usize,
    generation: u64,
    state: TaskInputUpdateState,
}
impl PartialEq for TaskInputJournalRecord {
    fn eq(&self, other: &Self) -> bool {
        self.binding == other.binding && self.task_id == other.task_id
            && self.created_at == other.created_at && self.history.entries == other.history.entries
            && self.history.bytes == other.history.bytes && self.ids == other.ids
            && self.last_id == other.last_id && self.pending_keys == other.pending_keys
            && self.acknowledged == other.acknowledged && self.generation == other.generation
            && self.state == other.state
    }
}
impl Eq for TaskInputJournalRecord {}
impl fmt::Debug for TaskInputJournalRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskInputJournalRecord").field("state", &self.state)
            .field("acknowledged_updates", &self.acknowledged)
            .field("generation", &self.generation).finish_non_exhaustive()
    }
}
impl TaskInputJournalRecord {
    /// Use only when protected storage authoritatively reports an absent slot,
    /// never as a replacement for a corrupt, unavailable or uncertain record.
    pub fn empty(binding: &TaskResumeBinding, task_id: TaskId) -> Result<Self, TaskInputJournalError> {
        Ok(Self {
            binding: associated_data(binding, &task_id)?, task_id, created_at: None,
            history: InputHistory::default(), ids: BTreeSet::new(), last_id: None,
            pending_keys: BTreeSet::new(), acknowledged: 0, generation: 0,
            state: TaskInputUpdateState::NotAttempted,
        })
    }
    pub fn update_state(&self) -> TaskInputUpdateState { self.state }
    pub fn acknowledged_updates(&self) -> usize { self.acknowledged }
    pub fn generation(&self) -> u64 { self.generation }

    fn validate(&self) -> Result<(), TaskInputJournalError> {
        if self.history.entries.len() > MAX_KEYS || self.ids.len() > MAX_UPDATES
            || self.acknowledged > MAX_UPDATES || self.pending_keys.len() > MAX_KEYS
        { return Err(TaskInputJournalError::Capacity); }
        let mut bytes = 0_usize;
        for key in self.history.entries.keys() {
            bytes = bytes.checked_add(key.len()).and_then(|n| n.checked_add(32))
                .filter(|n| *n <= MAX_INPUT_JOURNAL_BYTES).ok_or(TaskInputJournalError::Capacity)?;
        }
        if bytes != self.history.bytes { return Err(TaskInputJournalError::InvalidRecord); }
        let unconfirmed = self.state == TaskInputUpdateState::Unconfirmed;
        let pending = if unconfirmed { 1 } else { 0 };
        if self.generation != (self.acknowledged as u64) * 2 + pending as u64
            || self.ids.len() != self.acknowledged + pending
            || self.ids.iter().any(|id| id.is_empty() || id.len() > 256)
        { return Err(TaskInputJournalError::InvalidRecord); }
        if self.state == TaskInputUpdateState::NotAttempted {
            if self.generation != 0 || self.created_at.is_some() || self.last_id.is_some()
                || !self.history.entries.is_empty() || !self.pending_keys.is_empty()
            { return Err(TaskInputJournalError::InvalidRecord); }
            return Ok(());
        }
        let created = self.created_at.as_deref().ok_or(TaskInputJournalError::InvalidRecord)?;
        if created.len() > 64 { return Err(TaskInputJournalError::InvalidRecord); }
        TaskTimestamp::parse(created).map_err(|_| TaskInputJournalError::InvalidRecord)?;
        if !self.last_id.as_ref().is_some_and(|id| self.ids.contains(id))
            || (self.state == TaskInputUpdateState::Acknowledged && self.acknowledged == 0)
            || unconfirmed == self.pending_keys.is_empty()
            || self.history.entries.values().filter(|(_, answered)| *answered).count() < self.acknowledged
            || self.pending_keys.iter().any(|key|
                !self.history.entries.get(key).is_some_and(|(_, answered)| !answered))
        { return Err(TaskInputJournalError::InvalidRecord); }
        Ok(())
    }

    /// Plaintext controls for the mandatory host protector, NOT safe storage.
    pub fn encode(&self) -> Result<Vec<u8>, TaskInputJournalError> {
        self.validate()?;
        let mut out = Writer(Vec::new());
        out.bytes(MAGIC)?;
        out.bytes(&self.binding)?;
        out.text(self.task_id.as_str())?;
        out.text(self.created_at.as_deref().unwrap_or(""))?;
        out.bytes(&[match self.state { TaskInputUpdateState::NotAttempted => 0,
            TaskInputUpdateState::Unconfirmed => 1, TaskInputUpdateState::Acknowledged => 2 }])?;
        out.bytes(&(self.acknowledged as u16).to_be_bytes())?;
        out.bytes(&self.generation.to_be_bytes())?;
        out.text(self.last_id.as_deref().unwrap_or(""))?;
        out.bytes(&(self.ids.len() as u16).to_be_bytes())?;
        for id in &self.ids { out.text(id)?; }
        out.bytes(&(self.history.entries.len() as u16).to_be_bytes())?;
        for (key, (digest, answered)) in &self.history.entries {
            out.text(key)?; out.bytes(digest)?; out.bytes(&[u8::from(*answered)])?;
        }
        out.bytes(&(self.pending_keys.len() as u16).to_be_bytes())?;
        for key in &self.pending_keys { out.text(key)?; }
        Ok(out.0)
    }

    /// Strict bounded decoding AFTER authenticated decryption. Host identity
    /// is supplied independently; stored controls cannot select an account.
    pub fn decode(bytes: &[u8]) -> Result<Self, TaskInputJournalError> {
        if bytes.len() > MAX_INPUT_JOURNAL_BYTES { return Err(TaskInputJournalError::Capacity); }
        let mut input = Reader(bytes);
        if input.take(8)? != MAGIC { return Err(TaskInputJournalError::InvalidRecord); }
        let binding = input.take(32)?.try_into().map_err(|_| TaskInputJournalError::InvalidRecord)?;
        let task_id = TaskId::parse(input.text(1024)?).map_err(|_| TaskInputJournalError::InvalidRecord)?;
        let created_at = optional(input.text(64)?);
        let state = match input.byte()? { 0 => TaskInputUpdateState::NotAttempted,
            1 => TaskInputUpdateState::Unconfirmed, 2 => TaskInputUpdateState::Acknowledged,
            _ => return Err(TaskInputJournalError::InvalidRecord) };
        let acknowledged = input.count(MAX_UPDATES)?;
        let generation = u64::from_be_bytes(input.take(8)?.try_into().map_err(|_| TaskInputJournalError::InvalidRecord)?);
        let last_id = optional(input.text(256)?);
        let count = input.count(MAX_UPDATES)?;
        let mut ids = BTreeSet::new();
        for _ in 0..count { ordered_insert(&mut ids, input.text(256)?)?; }
        let count = input.count(MAX_KEYS)?;
        let mut history = InputHistory::default();
        for _ in 0..count {
            let key = input.text(MAX_INPUT_JOURNAL_BYTES)?;
            if history.entries.last_key_value().is_some_and(|(previous, _)| previous >= &key) {
                return Err(TaskInputJournalError::InvalidRecord);
            }
            let digest = input.take(32)?.try_into().map_err(|_| TaskInputJournalError::InvalidRecord)?;
            let answered = match input.byte()? { 0 => false, 1 => true,
                _ => return Err(TaskInputJournalError::InvalidRecord) };
            history.bytes = history.bytes.checked_add(key.len()).and_then(|n| n.checked_add(32))
                .ok_or(TaskInputJournalError::Capacity)?;
            history.entries.insert(key, (digest, answered));
        }
        let count = input.count(MAX_KEYS)?;
        let mut pending_keys = BTreeSet::new();
        for _ in 0..count { ordered_insert(&mut pending_keys, input.text(MAX_INPUT_JOURNAL_BYTES)?)?; }
        if !input.0.is_empty() { return Err(TaskInputJournalError::InvalidRecord); }
        let record = Self { binding, task_id, created_at, history, ids, last_id, pending_keys,
            acknowledged, generation, state };
        record.validate()?;
        Ok(record)
    }
}

/// Immutable conditional replacement. Only the driver can create a successor.
/// Providers must compare the complete expected record and atomically persist
/// the proposed record. Reapplying a consumed change is a conflict, not a retry.
#[derive(Clone, Debug)]
pub struct TaskInputJournalChange { expected: TaskInputJournalRecord, proposed: TaskInputJournalRecord }
impl TaskInputJournalChange {
    pub fn expected(&self) -> &TaskInputJournalRecord { &self.expected }
    pub fn proposed(&self) -> &TaskInputJournalRecord { &self.proposed }
}

pub type TaskInputJournalFuture<'a> = Pin<Box<dyn Future<Output = Result<TaskInputJournalRecord, TaskInputJournalError>> + Send + 'a>>;

/// A host-owned persistence boundary. Success MUST follow durable conditional
/// commit of exactly proposed(). Cancellation/error may follow a committed
/// write and must never authorize replay. Keep the same exclusive store for
/// the driver's lifetime. Blocking I/O must run in the caller's owned lane.
pub trait TaskInputJournalPersistence: Send {
    fn commit<'a>(&'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        deadline: Time, change: TaskInputJournalChange) -> TaskInputJournalFuture<'a>;
}

// Owned arguments let a host schedule its blocking store without borrowing an
// async poll stack or installing a library runtime. No default sink is supplied.
impl<F, T> TaskInputJournalPersistence for F
where
    F: FnMut(Cx, McpRequestCancellation, Time, TaskInputJournalChange) -> T + Send,
    T: Future<Output = Result<TaskInputJournalRecord, TaskInputJournalError>> + Send + 'static,
{
    fn commit<'a>(&'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        deadline: Time, change: TaskInputJournalChange) -> TaskInputJournalFuture<'a>
    { Box::pin(self(cx.clone(), cancellation.clone(), deadline, change)) }
}

/// One exclusive journal session. Failed/abandoned saves quarantine this value
/// before invoking host code. Reopen/reconcile the actual protected store rather
/// than restoring its last cached predecessor. There is no reset/clear API.
pub struct TaskInputJournal {
    binding: TaskResumeBinding,
    record: TaskInputJournalRecord,
    pending: Option<TaskInputJournalChange>,
    persistence: Box<dyn TaskInputJournalPersistence>,
}

// Authentication-independent transfer of admitted controls. Both drivers keep
// their own transport/policy types; neither needs to fabricate an OAuth policy
// or maintain a second journal codec, state machine or persistence contract.
pub(crate) struct TaskInputJournalState {
    pub(crate) entries: BTreeMap<String, ([u8; 32], bool)>,
    pub(crate) bytes: usize,
    pub(crate) state: TaskInputUpdateState,
    pub(crate) acknowledged: usize,
    pub(crate) request_id: Option<RequestId>,
}
impl fmt::Debug for TaskInputJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskInputJournal").field("record", &self.record)
            .field("requires_reconciliation", &self.pending.is_some()).finish_non_exhaustive()
    }
}
impl TaskInputJournal {
    pub fn new(binding: TaskResumeBinding, record: TaskInputJournalRecord,
        persistence: impl TaskInputJournalPersistence + 'static) -> Result<Self, TaskInputJournalError>
    {
        record.validate()?;
        if record.binding != associated_data(&binding, &record.task_id)? {
            return Err(TaskInputJournalError::BindingMismatch);
        }
        Ok(Self { binding, record, pending: None, persistence: Box::new(persistence) })
    }
    /// A pending conditional write is evidence of storage uncertainty, not the
    /// remote update's disposition. It remains inspectable after future drop.
    pub fn pending_change(&self) -> Option<&TaskInputJournalChange> { self.pending.as_ref() }
    pub fn record(&self) -> Result<&TaskInputJournalRecord, TaskInputJournalError> {
        if self.pending.is_some() { return Err(TaskInputJournalError::ReconciliationRequired); }
        Ok(&self.record)
    }
    pub(super) fn admit(&self, resource: &CanonicalHttpUrl, task: &TaskId,
        policy: ManagedTaskWatchDrivePolicy) -> Result<InputHistory, TaskInputJournalError>
    {
        let state = self.admit_driver(resource, task, policy.maximum_updates,
            policy.maximum_input_keys, policy.maximum_input_bytes)?;
        Ok(InputHistory { entries: state.entries, bytes: state.bytes })
    }
    pub(crate) fn admit_driver(&self, resource: &CanonicalHttpUrl, task: &TaskId,
        maximum_updates: usize, maximum_input_keys: usize, maximum_input_bytes: usize,
    ) -> Result<TaskInputJournalState, TaskInputJournalError>
    {
        let record = self.record()?;
        if resource.as_str() != self.binding.resource().as_str() || task != &record.task_id {
            return Err(TaskInputJournalError::BindingMismatch);
        }
        if record.history.entries.len() > maximum_input_keys
            || record.history.bytes > maximum_input_bytes
            || record.acknowledged > maximum_updates
        { return Err(TaskInputJournalError::Capacity); }
        Ok(TaskInputJournalState {
            entries: record.history.entries.clone(), bytes: record.history.bytes,
            state: record.state, acknowledged: record.acknowledged,
            request_id: record.last_id.clone().map(RequestId::String),
        })
    }
    pub(crate) fn check_task(&self, task: &Task) -> Result<(), TaskInputJournalError> {
        if self.record.task_id != task.base().task_id
            || self.record.created_at.as_ref().is_some_and(|created| created != task.base().created_at.as_str())
        { return Err(TaskInputJournalError::TaskChanged); }
        Ok(())
    }
    pub(crate) fn can_update(&self) -> Result<(), TaskInputJournalError> {
        if self.record()?.state == TaskInputUpdateState::Unconfirmed {
            return Err(TaskInputJournalError::ReconciliationRequired);
        }
        Ok(())
    }
    pub(super) fn restore_progress(&self) -> super::UpdateProgress {
        super::UpdateProgress { state: self.record.state, acknowledged: self.record.acknowledged,
            request_id: self.record.last_id.clone().map(RequestId::String) }
    }
    pub(super) fn intent(&self, task: &Task, history: &InputHistory,
        keys: impl Iterator<Item = String>, id: &RequestId,
    ) -> Result<TaskInputJournalChange, TaskInputJournalError> {
        self.intent_from_history(task, &history.entries, history.bytes, keys, id)
    }
    pub(crate) fn intent_from_history(&self, task: &Task,
        entries: &BTreeMap<String, ([u8; 32], bool)>, bytes: usize,
        keys: impl Iterator<Item = String>, id: &RequestId,
    ) -> Result<TaskInputJournalChange, TaskInputJournalError> {
        self.can_update()?;
        self.check_task(task)?;
        let RequestId::String(id) = id else { return Err(TaskInputJournalError::InvalidRecord); };
        if self.record.ids.contains(id) { return Err(TaskInputJournalError::IdentityReused); }
        if self.record.acknowledged >= MAX_UPDATES { return Err(TaskInputJournalError::Capacity); }
        // A successor cannot erase or rewrite an already-recorded descriptor.
        if self.record.history.entries.iter().any(|(key, entry)| entries.get(key) != Some(entry)) {
            return Err(TaskInputJournalError::InvalidRecord);
        }
        let mut proposed = self.record.clone();
        proposed.created_at = Some(task.base().created_at.as_str().to_owned());
        proposed.history = InputHistory { entries: entries.clone(), bytes };
        proposed.pending_keys = keys.collect();
        proposed.ids.insert(id.clone());
        proposed.last_id = Some(id.clone());
        proposed.generation += 1;
        proposed.state = TaskInputUpdateState::Unconfirmed;
        proposed.encode()?;
        Ok(TaskInputJournalChange { expected: self.record.clone(), proposed })
    }
    pub(crate) fn acknowledgement(&self) -> Result<TaskInputJournalChange, TaskInputJournalError> {
        let current = self.record()?;
        if current.state != TaskInputUpdateState::Unconfirmed { return Err(TaskInputJournalError::InvalidRecord); }
        let mut proposed = current.clone();
        for key in &proposed.pending_keys {
            proposed.history.entries.get_mut(key).ok_or(TaskInputJournalError::InvalidRecord)?.1 = true;
        }
        proposed.pending_keys.clear();
        proposed.acknowledged += 1;
        proposed.generation += 1;
        proposed.state = TaskInputUpdateState::Acknowledged;
        proposed.encode()?;
        Ok(TaskInputJournalChange { expected: current.clone(), proposed })
    }
    pub(crate) async fn persist(&mut self, cx: &Cx, cancellation: &McpRequestCancellation,
        deadline: Time, change: TaskInputJournalChange) -> Result<(), TaskInputJournalError>
    {
        check(cx, cancellation, deadline)?;
        if self.pending.is_some() || self.record != change.expected {
            return Err(TaskInputJournalError::ReconciliationRequired);
        }
        self.pending = Some(change.clone());
        let stored = self.persistence.commit(cx, cancellation, deadline, change.clone()).await?;
        if stored != change.proposed { return Err(TaskInputJournalError::InvalidReceipt); }
        // An admitted durable receipt survives a subsequent cancellation check.
        self.record = stored;
        self.pending = None;
        Ok(())
    }
}

pub(super) fn check(cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time)
    -> Result<(), TaskInputJournalError>
{
    if cancellation.is_cancel_requested() || cx.checkpoint().is_err() { return Err(TaskInputJournalError::Cancelled); }
    let deadline = cx.budget().deadline.map_or(deadline, |parent| parent.min(deadline));
    if cx.now() >= deadline { return Err(TaskInputJournalError::TimedOut); }
    Ok(())
}
fn associated_data(binding: &TaskResumeBinding, task: &TaskId) -> Result<[u8; 32], TaskInputJournalError> {
    let mut bytes = b"fastmcp/task-input-journal/v1\0".to_vec();
    bytes.extend_from_slice(binding.associated_data());
    bytes.extend_from_slice(&(task.as_str().len() as u32).to_be_bytes());
    bytes.extend_from_slice(task.as_str().as_bytes());
    sha256_bounded(&bytes, 1200).map(|digest| digest.into_bytes()).map_err(|_| TaskInputJournalError::BindingMismatch)
}
fn optional(text: String) -> Option<String> { if text.is_empty() { None } else { Some(text) } }
fn ordered_insert(set: &mut BTreeSet<String>, text: String) -> Result<(), TaskInputJournalError> {
    if set.last().is_some_and(|last| last >= &text) { return Err(TaskInputJournalError::InvalidRecord); }
    set.insert(text); Ok(())
}
struct Writer(Vec<u8>);
impl Writer {
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), TaskInputJournalError> {
        if bytes.len() > MAX_INPUT_JOURNAL_BYTES.saturating_sub(self.0.len()) { return Err(TaskInputJournalError::Capacity); }
        self.0.extend_from_slice(bytes); Ok(())
    }
    fn text(&mut self, text: &str) -> Result<(), TaskInputJournalError> {
        let length = u32::try_from(text.len()).map_err(|_| TaskInputJournalError::Capacity)?;
        self.bytes(&length.to_be_bytes())?; self.bytes(text.as_bytes())
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], TaskInputJournalError> {
        if count > self.0.len() { return Err(TaskInputJournalError::InvalidRecord); }
        let (value, rest) = self.0.split_at(count); self.0 = rest; Ok(value)
    }
    fn byte(&mut self) -> Result<u8, TaskInputJournalError> { Ok(self.take(1)?[0]) }
    fn count(&mut self, maximum: usize) -> Result<usize, TaskInputJournalError> {
        let count = usize::from(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| TaskInputJournalError::InvalidRecord)?));
        if count > maximum { return Err(TaskInputJournalError::Capacity); } Ok(count)
    }
    fn text(&mut self, maximum: usize) -> Result<String, TaskInputJournalError> {
        let count = u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| TaskInputJournalError::InvalidRecord)?);
        let count = usize::try_from(count).map_err(|_| TaskInputJournalError::Capacity)?;
        if count > maximum { return Err(TaskInputJournalError::Capacity); }
        std::str::from_utf8(self.take(count)?).map(str::to_owned).map_err(|_| TaskInputJournalError::InvalidRecord)
    }
}

#[cfg(test)]
mod tests;
