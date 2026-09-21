//! Bound, payload-free checkpoints for explicit Task restart recovery.
//!
//! A checkpoint is a lookup hint, never a credential or permission to replay
//! the creating call. It keeps only an opaque Task ID and lifecycle controls.
//! Tool arguments/results, input descriptors/answers, status messages, request
//! metadata and bearer material cannot enter this encoding.
//!
//! The host must construct the binding from its CURRENT verified account and
//! deployment configuration, not from a file being opened. The opaque owner
//! key alone is not authorization. A restored checkpoint must be reconciled
//! through live authenticated Tasks discovery/get before any host action.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use fastmcp_core::partition::DurableOwnerKey;
use fastmcp_core::{CanonicalHttpUrl, sha256_bounded};
use fastmcp_protocol::tasks_extension::{Task, TaskId, TaskStatus, TaskTimestamp};

/// Linux storage using the existing owner-private atomic-file primitive.
#[cfg(target_os = "linux")]
pub mod store;
/// Fresh authenticated reconciliation before consuming a restored record.
pub mod client;

/// Hard ceiling for one encoded checkpoint, independent of store capacity.
pub const MAX_TASK_RESUME_RECORD_BYTES: usize = 256 * 1024;
const MAX_RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);
const RECORD_MAGIC: &[u8; 8] = b"FMTRSM01";

/// Opaque, domain-separated lookup identity. These bytes confer no authority.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct TaskResumeKey([u8; 32]);

impl TaskResumeKey {
    /// Restores a selector, not a trusted record or authenticated account.
    pub fn from_bytes(bytes: [u8; 32]) -> Self { Self(bytes) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}
impl fmt::Debug for TaskResumeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskResumeKey(<opaque>)")
    }
}

/// Host-verified restart namespace, separate from a rotating bearer token.
///
/// The host is responsible for associating `owner` with the active login.
/// `auth_profile` identifies the stable authentication configuration and
/// `policy_revision` must cover the endpoint/profile/limits/authorization
/// policy in force. `protection_profile` identifies the configured durable
/// protector. Changing any of these intentionally makes old records unusable.
/// None of these identities is learned from the stored checkpoint.
#[derive(Clone)]
pub struct TaskResumeBinding {
    resource: CanonicalHttpUrl,
    digest: [u8; 32],
    protection_profile: [u8; 32],
}

impl TaskResumeBinding {
    pub fn from_verified_owner(
        resource: CanonicalHttpUrl,
        namespace: &str,
        owner: &DurableOwnerKey,
        auth_profile: [u8; 32],
        policy_revision: [u8; 32],
        protection_profile: [u8; 32],
    ) -> Result<Self, TaskResumeError> {
        Self::derive(resource, namespace, owner.as_bytes(), auth_profile,
            policy_revision, protection_profile)
    }

    fn derive(
        resource: CanonicalHttpUrl,
        namespace: &str,
        owner: &[u8; 32],
        auth_profile: [u8; 32],
        policy_revision: [u8; 32],
        protection_profile: [u8; 32],
    ) -> Result<Self, TaskResumeError> {
        if !resource.as_str().starts_with("https://") || resource.as_str().len() > 4096
            || namespace.is_empty() || namespace.len() > 128
            || !namespace.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        {
            return Err(TaskResumeError::InvalidBinding);
        }
        let mut source = b"fastmcp/task-resume-binding/v1\0modern-2026-07-28\0".to_vec();
        put_text(&mut source, resource.as_str())?;
        put_text(&mut source, namespace)?;
        source.extend_from_slice(owner);
        source.extend_from_slice(&auth_profile);
        source.extend_from_slice(&policy_revision);
        source.extend_from_slice(&protection_profile);
        let digest = sha256_bounded(&source, 4608)
            .map_err(|_| TaskResumeError::InvalidBinding)?.into_bytes();
        Ok(Self { resource, digest, protection_profile })
    }

    /// Associated data for the configured protector, not a cryptographic key.
    pub fn associated_data(&self) -> &[u8; 32] { &self.digest }
    pub fn resource(&self) -> &CanonicalHttpUrl { &self.resource }
    pub fn protection_profile(&self) -> &[u8; 32] { &self.protection_profile }
}
impl fmt::Debug for TaskResumeBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskResumeBinding(<verified host configuration>)")
    }
}

/// Fixed-schema control record. No general JSON map or Task payload is stored.
/// Exact admitted timestamp and Task-ID spellings survive the round trip.
#[derive(Clone, Eq, PartialEq)]
pub struct TaskResumeRecord {
    binding: [u8; 32],
    task_id: TaskId,
    status: TaskStatus,
    created_at: TaskTimestamp,
    updated_at: TaskTimestamp,
    ttl_ms: Option<u64>,
    poll_interval_ms: Option<u64>,
    retain_until: i128,
}
impl fmt::Debug for TaskResumeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskResumeRecord").field("status", &self.status).finish_non_exhaustive()
    }
}

impl TaskResumeRecord {
    /// Captures an admitted NONTERMINAL Task without touching its application
    /// payload. Null-TTL tasks still get a finite host retention bound. Finite
    /// TTL retention is measured from createdAt, never from lastUpdatedAt.
    pub fn capture(
        cx: &Cx,
        binding: &TaskResumeBinding,
        task: &Task,
        maximum_retention: Duration,
    ) -> Result<Self, TaskResumeError> {
        checkpoint(cx)?;
        Self::capture_at(binding, task, maximum_retention, wall_now())
    }

    fn capture_at(
        binding: &TaskResumeBinding,
        task: &Task,
        maximum_retention: Duration,
        now: i128,
    ) -> Result<Self, TaskResumeError> {
        if maximum_retention.is_zero() || maximum_retention > MAX_RETENTION {
            return Err(TaskResumeError::InvalidRetention);
        }
        let base = task.base();
        if !matches!((task, base.status),
            (Task::Working(_), TaskStatus::Working)
            | (Task::InputRequired { .. }, TaskStatus::InputRequired))
        {
            return Err(TaskResumeError::NotResumable);
        }
        let ttl_ms = base.ttl_ms.as_ref().map(|ttl| ttl.try_as_millis())
            .transpose().map_err(|_| TaskResumeError::InvalidRecord)?;
        let poll_interval_ms = base.poll_interval_ms.as_ref().map(|hint| hint.try_as_millis())
            .transpose().map_err(|_| TaskResumeError::InvalidRecord)?;
        let mut retain_until = now.checked_add(duration_nanos(maximum_retention))
            .ok_or(TaskResumeError::InvalidRetention)?;
        if let Some(ttl) = ttl_ms {
            retain_until = retain_until.min(timestamp_nanos(&base.created_at)?
                .checked_add(i128::from(ttl) * 1_000_000).ok_or(TaskResumeError::InvalidRecord)?);
        }
        let record = Self {
            binding: binding.digest, task_id: base.task_id.clone(), status: base.status,
            created_at: base.created_at.clone(), updated_at: base.last_updated_at.clone(),
            ttl_ms, poll_interval_ms, retain_until,
        };
        record.validate()?;
        record.admit_at(binding, now)?;
        Ok(record)
    }

    pub fn task_id(&self) -> &TaskId { &self.task_id }
    pub fn status(&self) -> TaskStatus { self.status }

    pub fn key(&self) -> TaskResumeKey {
        // TaskId already bounds the decoded UTF-8 to 1024 bytes. No delimiter
        // ambiguity or Unicode normalization can merge distinct peer IDs.
        let mut bytes = b"fastmcp/task-resume-key/v1\0".to_vec();
        bytes.extend_from_slice(&self.binding);
        bytes.extend_from_slice(&(self.task_id.as_str().len() as u16).to_be_bytes());
        bytes.extend_from_slice(self.task_id.as_str().as_bytes());
        TaskResumeKey(sha256_bounded(&bytes, 1200)
            .expect("typed Task ID and fixed binding fit the key encoding").into_bytes())
    }

    fn validate(&self) -> Result<(), TaskResumeError> {
        if !matches!(self.status, TaskStatus::Working | TaskStatus::InputRequired)
            || self.ttl_ms == Some(0) || self.poll_interval_ms == Some(0)
        { return Err(TaskResumeError::InvalidRecord); }
        let created = timestamp_nanos(&self.created_at)?;
        let updated = timestamp_nanos(&self.updated_at)?;
        if updated < created || self.retain_until <= created {
            return Err(TaskResumeError::InvalidRecord);
        }
        if let Some(ttl) = self.ttl_ms {
            let expiry = created.checked_add(i128::from(ttl) * 1_000_000)
                .ok_or(TaskResumeError::InvalidRecord)?;
            if self.retain_until > expiry || updated >= expiry {
                return Err(TaskResumeError::InvalidRecord);
            }
        }
        Ok(())
    }

    /// Checks current host binding and expiry. This is local admission only;
    /// successful admission never substitutes for live remote authorization.
    pub fn admit(&self, cx: &Cx, binding: &TaskResumeBinding) -> Result<(), TaskResumeError> {
        checkpoint(cx)?;
        self.admit_at(binding, wall_now())
    }

    fn admit_at(&self, binding: &TaskResumeBinding, now: i128) -> Result<(), TaskResumeError> {
        if self.binding != binding.digest || now >= self.retain_until {
            return Err(TaskResumeError::Unavailable);
        }
        Ok(())
    }

    /// Encodes plaintext controls for a host protector or explicit export.
    /// These bytes are NOT encrypted or authenticated. Do not persist them
    /// directly; the file adapter passes them to its mandatory protector.
    pub fn encode(&self) -> Result<Vec<u8>, TaskResumeError> {
        self.validate()?;
        let mut bytes = RECORD_MAGIC.to_vec();
        bytes.extend_from_slice(&self.binding);
        bytes.push(match self.status { TaskStatus::Working => 0, TaskStatus::InputRequired => 1,
            _ => return Err(TaskResumeError::InvalidRecord) });
        put_text(&mut bytes, self.task_id.as_str())?;
        put_text(&mut bytes, self.created_at.as_str())?;
        put_text(&mut bytes, self.updated_at.as_str())?;
        put_optional(&mut bytes, self.ttl_ms);
        put_optional(&mut bytes, self.poll_interval_ms);
        bytes.extend_from_slice(&self.retain_until.to_be_bytes());
        if bytes.len() > MAX_TASK_RESUME_RECORD_BYTES { return Err(TaskResumeError::TooLarge); }
        Ok(bytes)
    }

    /// Strict structural decoding, NOT authentication. The caller must first
    /// open protected bytes under its own expected binding and must subsequently
    /// call admit/reconcile against CURRENT authority, never a stored identity.
    pub fn decode(bytes: &[u8]) -> Result<Self, TaskResumeError> {
        if bytes.len() > MAX_TASK_RESUME_RECORD_BYTES { return Err(TaskResumeError::TooLarge); }
        let mut reader = Reader(bytes);
        if reader.take(8)? != RECORD_MAGIC { return Err(TaskResumeError::InvalidRecord); }
        let binding = reader.take(32)?.try_into().map_err(|_| TaskResumeError::InvalidRecord)?;
        let status = match reader.byte()? { 0 => TaskStatus::Working, 1 => TaskStatus::InputRequired,
            _ => return Err(TaskResumeError::InvalidRecord) };
        let task_id = TaskId::parse(reader.text(1024)?).map_err(|_| TaskResumeError::InvalidRecord)?;
        let created_at = TaskTimestamp::parse(reader.text(64)?).map_err(|_| TaskResumeError::InvalidRecord)?;
        let updated_at = TaskTimestamp::parse(reader.text(64)?).map_err(|_| TaskResumeError::InvalidRecord)?;
        let ttl_ms = reader.optional()?;
        let poll_interval_ms = reader.optional()?;
        let retain_until = i128::from_be_bytes(reader.take(16)?.try_into().map_err(|_| TaskResumeError::InvalidRecord)?);
        if !reader.0.is_empty() { return Err(TaskResumeError::InvalidRecord); }
        let record = Self { binding, task_id, status, created_at, updated_at, ttl_ms, poll_interval_ms, retain_until };
        record.validate()?;
        Ok(record)
    }
}

/// Redacted local failures; Unavailable deliberately merges wrong binding and
/// expired records. No error carries a stored Task ID or application payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskResumeError {
    InvalidBinding, InvalidRetention, InvalidRecord, TooLarge, Capacity,
    NotResumable, Unavailable, StaleSnapshot, ConflictingSnapshot,
    StaleCursor, Protection, ProcessChanged, Cancelled, TimedOut,
    RecoveryRequired, GenerationExhausted,
}
impl fmt::Display for TaskResumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidBinding => "invalid Task resume binding",
            Self::InvalidRetention => "invalid Task checkpoint retention",
            Self::InvalidRecord => "Task checkpoint is invalid",
            Self::TooLarge => "Task checkpoint bytes exceed their bound",
            Self::Capacity => "Task checkpoint capacity exhausted",
            Self::NotResumable => "only nonterminal Tasks can be checkpointed",
            Self::Unavailable => "Task checkpoint is unavailable",
            Self::StaleSnapshot => "Task checkpoint snapshot regressed",
            Self::ConflictingSnapshot => "Task checkpoint identity or snapshot conflicts",
            Self::StaleCursor => "Task checkpoint listing cursor is stale",
            Self::Protection => "Task checkpoint protection failed",
            Self::ProcessChanged => "Task checkpoint process generation changed",
            Self::Cancelled => "Task checkpoint operation cancelled",
            Self::TimedOut => "Task checkpoint operation timed out",
            Self::RecoveryRequired => "Task checkpoint store requires reconciliation",
            Self::GenerationExhausted => "Task checkpoint generations exhausted",
        })
    }
}
impl std::error::Error for TaskResumeError {}

fn checkpoint(cx: &Cx) -> Result<(), TaskResumeError> {
    cx.checkpoint().map_err(|_| TaskResumeError::Cancelled)?;
    if cx.budget().deadline.is_some_and(|deadline| cx.now() >= deadline) {
        return Err(TaskResumeError::TimedOut);
    }
    Ok(())
}
fn wall_now() -> i128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration_nanos(duration),
        Err(error) => -duration_nanos(error.duration()),
    }
}
fn duration_nanos(duration: Duration) -> i128 {
    i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos())
}

// Convert only an already-admitted timestamp; this is not a second parser.
// The Gregorian ordinal uses bounded arithmetic and preserves sub-millisecond
// precision. Offsets affect the instant, not the retained wire spelling.
fn timestamp_nanos(timestamp: &TaskTimestamp) -> Result<i128, TaskResumeError> {
    let text = timestamp.as_str();
    let number = |range: std::ops::Range<usize>| -> Result<i128, TaskResumeError> {
        text.get(range).ok_or(TaskResumeError::InvalidRecord)?.parse().map_err(|_| TaskResumeError::InvalidRecord)
    };
    let year = number(0..4)?;
    let month = usize::try_from(number(5..7)?).map_err(|_| TaskResumeError::InvalidRecord)?;
    let day = number(8..10)?;
    let previous = year - 1;
    let mut days = 365 * previous + previous / 4 - previous / 100 + previous / 400 - 719_162;
    let before_month = [0_i128, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    days += *before_month.get(month.checked_sub(1).ok_or(TaskResumeError::InvalidRecord)?)
        .ok_or(TaskResumeError::InvalidRecord)? + day - 1;
    if month > 2 && (year % 400 == 0 || (year % 4 == 0 && year % 100 != 0)) { days += 1; }
    let mut seconds = days * 86400 + number(11..13)? * 3600 + number(14..16)? * 60 + number(17..19)?;
    let bytes = text.as_bytes();
    let mut zone = 19;
    let mut fraction = 0_i128;
    if bytes.get(zone) == Some(&b'.') {
        zone += 1;
        let start = zone;
        while bytes.get(zone).is_some_and(u8::is_ascii_digit) {
            fraction = fraction * 10 + i128::from(bytes[zone] - b'0');
            zone += 1;
        }
        let digits = u32::try_from(zone - start).map_err(|_| TaskResumeError::InvalidRecord)?;
        fraction *= 10_i128.pow(9_u32.checked_sub(digits).ok_or(TaskResumeError::InvalidRecord)?);
    }
    match bytes.get(zone) {
        Some(b'Z') => {},
        Some(sign @ (b'+' | b'-')) => {
            let offset = number(zone + 1..zone + 3)? * 3600 + number(zone + 4..zone + 6)? * 60;
            seconds += if *sign == b'+' { -offset } else { offset };
        }
        _ => return Err(TaskResumeError::InvalidRecord),
    }
    Ok(seconds * 1_000_000_000 + fraction)
}

fn put_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), TaskResumeError> {
    let length = u16::try_from(value.len()).map_err(|_| TaskResumeError::TooLarge)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}
fn put_optional(bytes: &mut Vec<u8>, value: Option<u64>) {
    bytes.push(u8::from(value.is_some()));
    if let Some(value) = value { bytes.extend_from_slice(&value.to_be_bytes()); }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], TaskResumeError> {
        let (head, tail) = self.0.split_at_checked(count).ok_or(TaskResumeError::InvalidRecord)?;
        self.0 = tail;
        Ok(head)
    }
    fn byte(&mut self) -> Result<u8, TaskResumeError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, TaskResumeError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| TaskResumeError::InvalidRecord)?))
    }
    fn text(&mut self, maximum: usize) -> Result<&'a str, TaskResumeError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > maximum { return Err(TaskResumeError::InvalidRecord); }
        std::str::from_utf8(self.take(length)?).map_err(|_| TaskResumeError::InvalidRecord)
    }
    fn optional(&mut self) -> Result<Option<u64>, TaskResumeError> {
        match self.byte()? {
            0 => Ok(None),
            1 => {
                let number = u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| TaskResumeError::InvalidRecord)?);
                if number == 0 { return Err(TaskResumeError::InvalidRecord); }
                Ok(Some(number))
            }
            _ => Err(TaskResumeError::InvalidRecord),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(super) fn binding(owner: u8) -> TaskResumeBinding {
        TaskResumeBinding::derive(CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap(),
            "app", &[owner; 32], [2; 32], [3; 32], [4; 32]).unwrap()
    }
    pub(super) fn now() -> i128 { timestamp_nanos(&TaskTimestamp::parse("2026-09-21T00:00:01Z").unwrap()).unwrap() }
    fn task(id: &str) -> Task {
        serde_json::from_value(json!({"taskId":id,"status":"input_required",
            "createdAt":"2026-09-21T00:00:00Z","lastUpdatedAt":"2026-09-21T00:00:01Z",
            "ttlMs":60000,"pollIntervalMs":2000,"statusMessage":"SECRET-MESSAGE",
            "inputRequests":{"SECRET-INPUT":{"method":"roots/list"}}})).unwrap()
    }
    pub(super) fn record() -> TaskResumeRecord {
        TaskResumeRecord::capture_at(&binding(1), &task("opaque / ID"), Duration::from_secs(120), now()).unwrap()
    }

    #[test]
    fn checkpoint_roundtrip_contains_only_control_fields() {
        let original = record();
        let bytes = original.encode().unwrap();
        let decoded = TaskResumeRecord::decode(&bytes).unwrap();
        assert!(decoded == original);
        assert_eq!(decoded.task_id().as_str(), "opaque / ID");
        assert_eq!(decoded.key(), original.key());
        assert!(!bytes.windows(6).any(|part| part == b"SECRET"));
        assert!(!format!("{decoded:?}").contains("opaque / ID"));
        assert_eq!(original.retain_until, now() + 59_000_000_000);
    }

    #[test]
    fn wrong_owner_and_expired_records_are_indistinguishable() {
        let original = record();
        assert_eq!(original.admit_at(&binding(2), now()), Err(TaskResumeError::Unavailable));
        assert_eq!(original.admit_at(&binding(1), original.retain_until), Err(TaskResumeError::Unavailable));
        assert!(original.admit_at(&binding(1), original.retain_until - 1).is_ok());
    }

    #[test]
    fn every_truncation_and_trailing_byte_is_rejected() {
        let bytes = record().encode().unwrap();
        for length in 0..bytes.len() { assert!(TaskResumeRecord::decode(&bytes[..length]).is_err()); }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(TaskResumeRecord::decode(&trailing).is_err());
        let mut terminal = bytes;
        terminal[40] = 2;
        assert!(TaskResumeRecord::decode(&terminal).is_err());
    }

    #[test]
    fn keys_bind_exact_unicode_ids_and_every_configuration_dimension() {
        let one = TaskResumeRecord::capture_at(&binding(1), &task("é"), Duration::from_secs(30), now()).unwrap();
        let two = TaskResumeRecord::capture_at(&binding(1), &task("e\u{301}"), Duration::from_secs(30), now()).unwrap();
        assert_ne!(one.key(), two.key());
        assert_ne!(one.key(), TaskResumeRecord::capture_at(&binding(2), &task("é"), Duration::from_secs(30), now()).unwrap().key());
        let baseline = binding(1);
        for (namespace, auth, policy, protector) in [
            ("other", [2; 32], [3; 32], [4; 32]), ("app", [5; 32], [3; 32], [4; 32]),
            ("app", [2; 32], [5; 32], [4; 32]), ("app", [2; 32], [3; 32], [5; 32]),
        ] {
            let changed = TaskResumeBinding::derive(baseline.resource.clone(), namespace, &[1; 32], auth, policy, protector).unwrap();
            assert_ne!(baseline.digest, changed.digest);
        }
    }

    #[test]
    fn timestamp_instants_use_offsets_and_nanoseconds_not_lexical_order() {
        let instant = |text| timestamp_nanos(&TaskTimestamp::parse(text).unwrap()).unwrap();
        assert_eq!(instant("1970-01-01T00:00:00Z"), 0);
        assert_eq!(instant("1969-12-31T23:59:59.999999999Z"), -1);
        assert_eq!(instant("2024-03-01T01:00:00+01:00"), instant("2024-03-01T00:00:00Z"));
        assert_eq!(instant("2024-03-01T00:00:00Z") - instant("2024-02-28T00:00:00Z"), 172800_000_000_000);
        assert_eq!(instant("2100-03-01T00:00:00Z") - instant("2100-02-28T00:00:00Z"), 86400_000_000_000);
        assert_eq!(instant("2000-03-01T00:00:00.1Z") - instant("2000-02-29T00:00:00Z"), 86400_100_000_000);
    }

    #[test]
    fn null_ttl_still_has_finite_retention_and_terminal_data_is_not_captured() {
        let mut snapshot = task("one");
        if let Task::InputRequired { base, .. } = &mut snapshot { base.ttl_ms = None; }
        let retained = TaskResumeRecord::capture_at(&binding(1), &snapshot, Duration::from_secs(10), now()).unwrap();
        assert_eq!(retained.retain_until, now() + 10_000_000_000);
        assert!(TaskResumeRecord::capture_at(&binding(1), &snapshot, Duration::ZERO, now()).is_err());
        let terminal = Task::Cancelled(snapshot.base().clone());
        assert!(matches!(TaskResumeRecord::capture_at(&binding(1), &terminal, Duration::from_secs(10), now()), Err(TaskResumeError::NotResumable)));
    }
}
