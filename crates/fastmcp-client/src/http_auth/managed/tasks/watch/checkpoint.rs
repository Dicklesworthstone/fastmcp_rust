//! Portable, observation-only restart checkpoints for already-created Tasks.
//!
//! These bytes are a selection, NOT a credential, execution receipt or replay
//! permit. Restore uses a caller-selected managed login at the exact recorded
//! resource, opens a fresh acknowledged subscription, and reads current Tasks.
//! No saved snapshot, terminal ledger, token, input answer, requestState or
//! creating request is restored. A Task that disappeared or became forbidden
//! remains an ordinary server error; it is never recreated or declared complete.
//!
//! The host owns durable storage, access control and atomic replacement of the
//! bytes. Task IDs and resource URLs can be sensitive even without credentials.
//! Export does not close a watch or acknowledge delivery. Restoring starts a NEW
//! observation budget and may redeliver terminal snapshots; exactly-once effects,
//! missed-event replay and persistence of a remote Task are not implied.

use std::fmt;

use asupersync::Cx;
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::FINAL_PROTOCOL_VERSION;
use fastmcp_protocol::tasks_extension::TaskId;
use serde::{Deserialize, Serialize};

use super::{
    BoundedWriter, ManagedTaskWatch, ManagedTaskWatchError, ManagedTaskWatchPolicy,
    ManagedTasksClient, WatchState, MAX_WATCH_TASKS,
};
use super::recovery::{
    ManagedTaskRecoveryError, ManagedTaskRecoveryPolicy, RecoveringManagedTaskWatch,
};

/// Hard bound checked before JSON parsing and while encoding a checkpoint.
pub const MAX_TASK_WATCH_CHECKPOINT_BYTES: usize = 64 * 1024;
const CHECKPOINT_FORMAT: &str = "fastmcp/task-watch";
const CHECKPOINT_VERSION: u32 = 1;

/// Immutable restart selection. Deliberately not `Deserialize`: all decoding
/// must pass the byte bound, exact format/era and selection admission below.
/// Debug output omits the endpoint and Task IDs.
#[derive(Clone)]
pub struct ManagedTaskWatchCheckpoint {
    resource: CanonicalHttpUrl,
    task_ids: Vec<TaskId>,
}

impl fmt::Debug for ManagedTaskWatchCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedTaskWatchCheckpoint")
            .field("version", &CHECKPOINT_VERSION)
            .field("task_count", &self.task_ids.len())
            .finish_non_exhaustive()
    }
}

// Deserialize the closed typed object directly, not through Value: repeated
// members (including escaped spellings) must not silently become last-wins.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CheckpointWire {
    format: String,
    version: u32,
    protocol_version: String,
    resource: String,
    task_ids: Vec<TaskId>,
}

/// Fixed checkpoint diagnostics retain neither saved bytes nor identifiers.
/// Live admission errors preserve their original typed cause.
#[derive(Debug)]
pub enum ManagedTaskCheckpointError {
    TooLarge,
    InvalidDocument,
    UnsupportedFormat,
    UnsupportedProtocol,
    InvalidResource,
    InvalidSelection,
    ResourceMismatch,
    Watch(ManagedTaskWatchError),
    Recovery(ManagedTaskRecoveryError),
}

impl fmt::Display for ManagedTaskCheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "Task watch checkpoint byte bound exceeded",
            Self::InvalidDocument => "invalid Task watch checkpoint document",
            Self::UnsupportedFormat => "unsupported Task watch checkpoint format or version",
            Self::UnsupportedProtocol => "unsupported Task watch checkpoint protocol era",
            Self::InvalidResource => "invalid Task watch checkpoint resource",
            Self::InvalidSelection => "invalid Task watch checkpoint selection",
            Self::ResourceMismatch => "Task watch checkpoint does not match the configured resource",
            Self::Watch(_) => "Task watch checkpoint admission failed",
            Self::Recovery(_) => "recovering Task watch checkpoint admission failed",
        })
    }
}

impl std::error::Error for ManagedTaskCheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Watch(error) => Some(error),
            Self::Recovery(error) => Some(error),
            _ => None,
        }
    }
}
impl From<ManagedTaskWatchError> for ManagedTaskCheckpointError {
    fn from(error: ManagedTaskWatchError) -> Self { Self::Watch(error) }
}
impl From<ManagedTaskRecoveryError> for ManagedTaskCheckpointError {
    fn from(error: ManagedTaskRecoveryError) -> Self { Self::Recovery(error) }
}

impl ManagedTaskWatchCheckpoint {
    fn new(resource: &CanonicalHttpUrl, task_ids: Vec<TaskId>) -> Result<Self, ManagedTaskCheckpointError> {
        // Reuse the live watch's exact uniqueness, cardinality and encoded
        // selection bounds. The restart policy will separately bound snapshots.
        let state = WatchState::new(task_ids, MAX_WATCH_TASKS)
            .map_err(|_| ManagedTaskCheckpointError::InvalidSelection)?;
        let checkpoint = Self { resource: resource.clone(), task_ids: state.task_ids };
        checkpoint.encode()?;
        Ok(checkpoint)
    }

    /// Decode one bounded closed-format document. This does not establish
    /// ownership or existence of any Task and performs no network or file I/O.
    pub fn decode(bytes: &[u8]) -> Result<Self, ManagedTaskCheckpointError> {
        if bytes.len() > MAX_TASK_WATCH_CHECKPOINT_BYTES {
            return Err(ManagedTaskCheckpointError::TooLarge);
        }
        let wire: CheckpointWire = serde_json::from_slice(bytes)
            .map_err(|_| ManagedTaskCheckpointError::InvalidDocument)?;
        if wire.format != CHECKPOINT_FORMAT || wire.version != CHECKPOINT_VERSION {
            return Err(ManagedTaskCheckpointError::UnsupportedFormat);
        }
        if wire.protocol_version != FINAL_PROTOCOL_VERSION {
            return Err(ManagedTaskCheckpointError::UnsupportedProtocol);
        }
        let resource = CanonicalHttpUrl::parse(&wire.resource)
            .map_err(|_| ManagedTaskCheckpointError::InvalidResource)?;
        if resource.as_str() != wire.resource {
            return Err(ManagedTaskCheckpointError::InvalidResource);
        }
        Self::new(&resource, wire.task_ids)
    }

    /// Encode a complete portable selection for host-owned storage. No runtime
    /// state, deadline, token, client policy or Task contents enters the bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ManagedTaskCheckpointError> {
        let wire = CheckpointWire {
            format: CHECKPOINT_FORMAT.to_owned(), version: CHECKPOINT_VERSION,
            protocol_version: FINAL_PROTOCOL_VERSION.to_owned(),
            resource: self.resource.as_str().to_owned(), task_ids: self.task_ids.clone(),
        };
        let mut writer = BoundedWriter { bytes: Vec::new(), maximum: MAX_TASK_WATCH_CHECKPOINT_BYTES };
        serde_json::to_writer(&mut writer, &wire).map_err(|_| ManagedTaskCheckpointError::TooLarge)?;
        Ok(writer.bytes)
    }

    /// Exact, canonical resource to inspect before explicitly choosing a login.
    /// Restore never constructs a client or discovers an endpoint from this URL.
    pub fn resource(&self) -> &CanonicalHttpUrl { &self.resource }

    /// All originally selected IDs, in reconciliation order. Completed IDs are
    /// not suppressed using untrusted persisted state after a restart.
    pub fn task_ids(&self) -> &[TaskId] { &self.task_ids }

    fn admit_resource(&self, resource: &CanonicalHttpUrl) -> Result<(), ManagedTaskCheckpointError> {
        if self.resource.as_str() != resource.as_str() {
            return Err(ManagedTaskCheckpointError::ResourceMismatch);
        }
        Ok(())
    }
}

impl ManagedTaskWatch {
    /// Export the original selection, including Tasks whose terminal snapshots
    /// were already delivered. Works after close/failure too; it does not revive
    /// the old stream, extend its deadline or grant authority to replay inputs.
    pub fn checkpoint(&self) -> Result<ManagedTaskWatchCheckpoint, ManagedTaskCheckpointError> {
        self.client.task_watch_checkpoint(self.state.task_ids.clone())
    }
}

impl ManagedTasksClient {
    /// Prepare restartable observation for known, already-created Task IDs.
    /// Persist this before starting a recovering or input-driving watch when
    /// the host needs to retain the selection independently of that owner.
    /// It is not available for an uncertain creation with no admitted Task ID.
    pub fn task_watch_checkpoint(
        &self, task_ids: Vec<TaskId>,
    ) -> Result<ManagedTaskWatchCheckpoint, ManagedTaskCheckpointError> {
        ManagedTaskWatchCheckpoint::new(self.session.resource(), task_ids)
    }

    /// Start a fresh observation from a checkpoint using THIS explicitly
    /// selected managed session. Exact resource equality is checked before
    /// credential acquisition or network access. Current login validity, Tasks
    /// discovery, full subscription acknowledgement and every authorized get
    /// are enforced by the ordinary watch path, never by saved data.
    ///
    /// Supply a new ID prefix and explicit finite observation policy. Old
    /// monotonic deadlines and delivery ledgers are not portable across restart.
    pub async fn resume_task_watch(
        &self, cx: &Cx, checkpoint: &ManagedTaskWatchCheckpoint,
        id_prefix: String, policy: ManagedTaskWatchPolicy,
    ) -> Result<ManagedTaskWatch, ManagedTaskCheckpointError> {
        self.resume_task_watch_with_cancellation(
            cx, &McpRequestCancellation::new(), checkpoint, id_prefix, policy,
        ).await
    }

    /// Cancellation remains local to observation; no remote cancellation or
    /// mutation is sent while restoring, reading, closing or dropping a watch.
    pub async fn resume_task_watch_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        checkpoint: &ManagedTaskWatchCheckpoint, id_prefix: String,
        policy: ManagedTaskWatchPolicy,
    ) -> Result<ManagedTaskWatch, ManagedTaskCheckpointError> {
        checkpoint.admit_resource(self.session.resource())?;
        Ok(self.watch_tasks_with_cancellation(
            cx, cancellation, checkpoint.task_ids.clone(), id_prefix, policy,
        ).await?)
    }

    /// Restore with the existing bounded, observation-only reconnect policy.
    /// The new finite watch budget spans all reconnects; checkpoint restore is
    /// not an automatic way to reset an exhausted owner's limits.
    pub async fn resume_task_watch_recovering(
        &self, cx: &Cx, checkpoint: &ManagedTaskWatchCheckpoint,
        id_prefix: String, policy: ManagedTaskWatchPolicy, recovery: ManagedTaskRecoveryPolicy,
    ) -> Result<RecoveringManagedTaskWatch, ManagedTaskCheckpointError> {
        self.resume_task_watch_recovering_with_cancellation(
            cx, &McpRequestCancellation::new(), checkpoint, id_prefix, policy, recovery,
        ).await
    }

    /// Restored admission, backoff and reconciliation share one caller-owned
    /// cancellation domain and preserve typed recovery/admission diagnostics.
    pub async fn resume_task_watch_recovering_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        checkpoint: &ManagedTaskWatchCheckpoint, id_prefix: String,
        policy: ManagedTaskWatchPolicy, recovery: ManagedTaskRecoveryPolicy,
    ) -> Result<RecoveringManagedTaskWatch, ManagedTaskCheckpointError> {
        checkpoint.admit_resource(self.session.resource())?;
        Ok(self.watch_tasks_recovering_with_cancellation(
            cx, cancellation, checkpoint.task_ids.clone(), id_prefix, policy, recovery,
        ).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn resource() -> CanonicalHttpUrl { CanonicalHttpUrl::parse("https://service.example/mcp").unwrap() }
    fn id(value: &str) -> TaskId { TaskId::parse(value).unwrap() }
    fn document() -> serde_json::Value {
        json!({"format":CHECKPOINT_FORMAT, "version":1, "protocolVersion":FINAL_PROTOCOL_VERSION,
            "resource":"https://service.example/mcp", "taskIds":["second", "first"]})
    }

    #[test]
    fn checkpoint_round_trip_preserves_exact_resource_and_selection_order() {
        let saved = ManagedTaskWatchCheckpoint::new(&resource(), vec![id("second"), id("first")]).unwrap();
        let encoded = saved.encode().unwrap();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(), document());
        let decoded = ManagedTaskWatchCheckpoint::decode(&encoded).unwrap();
        assert_eq!(decoded.resource(), &resource());
        assert_eq!(decoded.task_ids(), [id("second"), id("first")]);
        assert_eq!(decoded.encode().unwrap(), encoded);
        let debug = format!("{decoded:?}");
        assert!(debug.contains("task_count: 2"));
        for secret in ["service.example", "second", "first"] { assert!(!debug.contains(secret)); }
    }

    #[test]
    fn checkpoint_rejects_duplicate_unknown_missing_and_trailing_members() {
        let encoded = document().to_string();
        assert!(ManagedTaskWatchCheckpoint::decode(encoded.as_bytes()).is_ok());
        for suffix in [
            r#", "version":1"#, r#", "ver\u0073ion":1"#,
            r#", "taskIds":["second","first"]"#, r#", "terminal":[true,true]"#,
            r#", "accessToken":"secret""#, r#", "requestState":"secret""#,
        ] {
            let invalid = format!("{}{suffix}}}", &encoded[..encoded.len() - 1]);
            assert!(matches!(ManagedTaskWatchCheckpoint::decode(invalid.as_bytes()), Err(ManagedTaskCheckpointError::InvalidDocument)));
        }
        for field in ["format", "version", "protocolVersion", "resource", "taskIds"] {
            let mut missing = document();
            missing.as_object_mut().unwrap().remove(field);
            assert!(matches!(ManagedTaskWatchCheckpoint::decode(missing.to_string().as_bytes()), Err(ManagedTaskCheckpointError::InvalidDocument)));
        }
        for invalid in [format!("{encoded}{{}}"), "null".to_owned(), "[]".to_owned()] {
            assert!(matches!(ManagedTaskWatchCheckpoint::decode(invalid.as_bytes()), Err(ManagedTaskCheckpointError::InvalidDocument)));
        }
    }

    #[test]
    fn checkpoint_format_and_era_cannot_select_a_legacy_or_future_path() {
        for (field, value) in [("format", json!("other")), ("version", json!(0)), ("version", json!(2))] {
            let mut invalid = document();
            invalid[field] = value;
            assert!(matches!(ManagedTaskWatchCheckpoint::decode(invalid.to_string().as_bytes()), Err(ManagedTaskCheckpointError::UnsupportedFormat)));
        }
        for era in ["2024-11-05", "2025-11-25", "unknown"] {
            let mut invalid = document();
            invalid["protocolVersion"] = json!(era);
            assert!(matches!(ManagedTaskWatchCheckpoint::decode(invalid.to_string().as_bytes()), Err(ManagedTaskCheckpointError::UnsupportedProtocol)));
        }
    }

    #[test]
    fn checkpoint_selection_reuses_live_watch_cardinality_and_uniqueness_rules() {
        for count in [1, MAX_WATCH_TASKS] {
            let ids = (0..count).map(|n| id(&format!("task-{n}"))).collect();
            let checkpoint = ManagedTaskWatchCheckpoint::new(&resource(), ids).unwrap();
            assert_eq!(ManagedTaskWatchCheckpoint::decode(&checkpoint.encode().unwrap()).unwrap().task_ids().len(), count);
        }
        for ids in [vec![], vec![id("one"), id("one")], (0..=MAX_WATCH_TASKS).map(|n| id(&format!("task-{n}"))).collect()] {
            let mut invalid = document();
            invalid["taskIds"] = json!(ids);
            assert!(matches!(ManagedTaskWatchCheckpoint::decode(invalid.to_string().as_bytes()), Err(ManagedTaskCheckpointError::InvalidSelection)));
        }
    }

    #[test]
    fn checkpoint_resource_is_canonical_and_restore_checks_the_full_endpoint() {
        let checkpoint = ManagedTaskWatchCheckpoint::new(&resource(), vec![id("one")]).unwrap();
        assert!(checkpoint.admit_resource(&resource()).is_ok());
        for different in ["http://service.example/mcp", "https://other.example/mcp",
            "https://service.example:444/mcp", "https://service.example/other", "https://service.example/mcp?tenant=other"]
        {
            assert!(matches!(checkpoint.admit_resource(&CanonicalHttpUrl::parse(different).unwrap()), Err(ManagedTaskCheckpointError::ResourceMismatch)));
        }
        for repaired in ["https://SERVICE.example/mcp", "https://service.example:443/mcp", "not-a-url"] {
            let mut invalid = document();
            invalid["resource"] = json!(repaired);
            assert!(matches!(ManagedTaskWatchCheckpoint::decode(invalid.to_string().as_bytes()), Err(ManagedTaskCheckpointError::InvalidResource)));
        }
    }

    #[test]
    fn checkpoint_byte_limit_is_enforced_before_parsing_without_reflecting_input() {
        let mut bytes = document().to_string().into_bytes();
        bytes.resize(MAX_TASK_WATCH_CHECKPOINT_BYTES, b' ');
        assert!(ManagedTaskWatchCheckpoint::decode(&bytes).is_ok());
        bytes.push(b' ');
        assert!(matches!(ManagedTaskWatchCheckpoint::decode(&bytes), Err(ManagedTaskCheckpointError::TooLarge)));
        assert!(ManagedTaskWatchCheckpoint::decode(&[0xff]).is_err());
        let error = ManagedTaskWatchCheckpoint::decode(b"secret-not-json").unwrap_err();
        assert!(!format!("{error:?} {error}").contains("secret"));
    }
}
