//! Restart selection for an already-created DPoP-protected Task.
//!
//! A checkpoint contains an exact resource and Task ID, not a credential,
//! snapshot, continuation, input answer or permission to replay execution.
//! The host owns protected, atomic storage and explicitly chooses a current
//! DPoP client and credential when restoring. The saved resource is checked
//! against that client; it is never followed to construct a new connection.
//! Current authorization and the remote Task's existence remain server-owned.

/// Bounded, authenticated startup reconciliation of independently saved Tasks.
pub mod reconcile;
/// Owner-bound, retention-limited recovery from protected Task resume records.
pub mod resume;

use std::fmt;

use asupersync::Cx;
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::tasks_extension::TaskId;
use fastmcp_protocol::{FINAL_PROTOCOL_VERSION, FinalRequestMeta};
use serde::{Deserialize, Serialize};

use super::{DpopTaskWaitOutcome, DpopTaskWatchError, DpopTaskWatchPolicy};
use crate::http_auth::dpop::native::core::BoundedWriter;
use crate::http_auth::dpop::native::core::stream::DpopStreamLimits;
use crate::http_auth::dpop::native::{DpopCredential, DpopHttpClient, DpopHttpError};

/// Checked before decoding and during encoding, including JSON escaping.
pub const MAX_DPOP_TASK_CHECKPOINT_BYTES: usize = 64 * 1024;
const CHECKPOINT_FORMAT: &str = "fastmcp/dpop-task-watch";
const CHECKPOINT_VERSION: u32 = 1;

/// Immutable, observation-only restart selection. Debug omits identifiers.
///
/// Not `Deserialize`: all untrusted documents must pass [`Self::decode`].
/// The format intentionally carries no DPoP private key or access token. A
/// new explicitly chosen login may use a new key; it must still be authorized
/// for this Task by the server. A checkpoint is not proof of Task ownership.
#[derive(Clone)]
pub struct DpopTaskWatchCheckpoint {
    resource: CanonicalHttpUrl,
    task_id: TaskId,
}

impl fmt::Debug for DpopTaskWatchCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopTaskWatchCheckpoint")
            .field("version", &CHECKPOINT_VERSION)
            .finish_non_exhaustive()
    }
}

// Decode directly into a closed struct, never via Value. Repeated members,
// including escaped spellings, must not silently become last-wins.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CheckpointWire {
    format: String,
    version: u32,
    protocol_version: String,
    resource: String,
    task_id: TaskId,
}

/// Fixed checkpoint diagnostics do not retain saved bytes or identifiers.
/// Runtime failures preserve the ordinary watch's typed, sanitized cause.
#[derive(Debug)]
pub enum DpopTaskCheckpointError {
    TooLarge,
    InvalidDocument,
    UnsupportedFormat,
    UnsupportedProtocol,
    InvalidResource,
    ResourceMismatch,
    InvalidSelection,
    Watch(DpopTaskWatchError),
}

impl fmt::Display for DpopTaskCheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "DPoP Task checkpoint byte bound exceeded",
            Self::InvalidDocument => "invalid DPoP Task checkpoint document",
            Self::UnsupportedFormat => "unsupported DPoP Task checkpoint format or version",
            Self::UnsupportedProtocol => "unsupported DPoP Task checkpoint protocol era",
            Self::InvalidResource => "invalid DPoP Task checkpoint resource",
            Self::ResourceMismatch => "DPoP Task checkpoint does not match the configured resource",
            Self::InvalidSelection => "invalid DPoP Task checkpoint reconciliation selection",
            Self::Watch(_) => "DPoP Task checkpoint observation failed",
        })
    }
}

impl std::error::Error for DpopTaskCheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Watch(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DpopTaskWatchError> for DpopTaskCheckpointError {
    fn from(error: DpopTaskWatchError) -> Self {
        Self::Watch(error)
    }
}

impl DpopTaskWatchCheckpoint {
    /// Prepare observation of a known Task at an explicitly chosen resource.
    /// This does not establish that the Task exists or is accessible.
    ///
    /// Can be called from a creation observer before any successor operation.
    /// It must not be used to turn an uncertain creation into a new tool call.
    pub fn new(
        resource: &CanonicalHttpUrl,
        task_id: TaskId,
    ) -> Result<Self, DpopTaskCheckpointError> {
        // Bound before cloning the resource or building the encoding buffer.
        if resource.as_str().len() > MAX_DPOP_TASK_CHECKPOINT_BYTES {
            return Err(DpopTaskCheckpointError::TooLarge);
        }
        if !resource.as_str().starts_with("https://") {
            return Err(DpopTaskCheckpointError::InvalidResource);
        }
        let checkpoint = Self {
            resource: resource.clone(),
            task_id,
        };
        checkpoint.encode()?;
        Ok(checkpoint)
    }

    /// Admit one bounded, closed-format JSON object with an exact canonical
    /// HTTPS resource. Arrays, duplicate fields and saved execution state fail.
    /// Decoding performs no network, filesystem, credential or clock operation.
    pub fn decode(bytes: &[u8]) -> Result<Self, DpopTaskCheckpointError> {
        if bytes.len() > MAX_DPOP_TASK_CHECKPOINT_BYTES {
            return Err(DpopTaskCheckpointError::TooLarge);
        }
        // Serde's derived struct visitor also accepts positional sequences;
        // those are not part of this portable object format.
        if bytes.iter().copied().find(|byte| !byte.is_ascii_whitespace()) != Some(b'{') {
            return Err(DpopTaskCheckpointError::InvalidDocument);
        }
        let wire: CheckpointWire = serde_json::from_slice(bytes)
            .map_err(|_| DpopTaskCheckpointError::InvalidDocument)?;
        if wire.format != CHECKPOINT_FORMAT || wire.version != CHECKPOINT_VERSION {
            return Err(DpopTaskCheckpointError::UnsupportedFormat);
        }
        if wire.protocol_version != FINAL_PROTOCOL_VERSION {
            return Err(DpopTaskCheckpointError::UnsupportedProtocol);
        }
        let resource = CanonicalHttpUrl::parse(&wire.resource)
            .map_err(|_| DpopTaskCheckpointError::InvalidResource)?;
        if resource.as_str() != wire.resource {
            return Err(DpopTaskCheckpointError::InvalidResource);
        }
        Self::new(&resource, wire.task_id)
    }

    /// Encode for host-owned protected storage. Export does not close a watch,
    /// acknowledge delivery, extend its deadline, or make remote work durable.
    pub fn encode(&self) -> Result<Vec<u8>, DpopTaskCheckpointError> {
        let wire = CheckpointWire {
            format: CHECKPOINT_FORMAT.to_owned(),
            version: CHECKPOINT_VERSION,
            protocol_version: FINAL_PROTOCOL_VERSION.to_owned(),
            resource: self.resource.as_str().to_owned(),
            task_id: self.task_id.clone(),
        };
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            maximum: MAX_DPOP_TASK_CHECKPOINT_BYTES,
        };
        serde_json::to_writer(&mut writer, &wire)
            .map_err(|_| DpopTaskCheckpointError::TooLarge)?;
        Ok(writer.bytes)
    }

    /// Inspect before selecting a client. Restore never follows this URL.
    pub fn resource(&self) -> &CanonicalHttpUrl {
        &self.resource
    }

    /// Exact Task ID to reconcile, not a saved snapshot or continuation token.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    fn admit_resource(&self, resource: &CanonicalHttpUrl) -> Result<(), DpopTaskCheckpointError> {
        if self.resource.as_str() != resource.as_str() {
            return Err(DpopTaskCheckpointError::ResourceMismatch);
        }
        Ok(())
    }
}

impl DpopHttpClient {
    /// Prepare restartable observation of a known Task at this client's exact
    /// resource. Persist before observing when recovery must outlive the future.
    pub fn task_watch_checkpoint(
        &self,
        task_id: TaskId,
    ) -> Result<DpopTaskWatchCheckpoint, DpopTaskCheckpointError> {
        DpopTaskWatchCheckpoint::new(self.resource(), task_id)
    }

    /// Start a NEW observation using an explicitly selected current credential.
    ///
    /// A fresh authenticated get is authoritative; persisted data never supplies
    /// completion, input answers or authorization. Working Tasks use the ordinary
    /// acknowledged listen and post-acknowledgement get, closing the subscribe
    /// race. Missing/forbidden Tasks remain errors and are never recreated.
    ///
    /// Supply fresh request IDs through `id_prefix` and a finite new policy.
    /// This is an explicit restart, not an automatic reset of exhausted limits.
    /// Terminal snapshots can be delivered again; exactly-once host effects and
    /// missed-event replay are not implied. No refresh or mutation is performed.
    #[allow(clippy::too_many_arguments)]
    pub async fn resume_task_watch(
        &mut self,
        cx: &Cx,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        checkpoint: &DpopTaskWatchCheckpoint,
        id_prefix: &str,
        policy: DpopTaskWatchPolicy,
        limits: DpopStreamLimits,
    ) -> Result<DpopTaskWaitOutcome, DpopTaskCheckpointError> {
        self.resume_task_watch_with_cancellation(
            cx, &McpRequestCancellation::new(), credential, metadata, checkpoint,
            id_prefix, policy, limits,
        ).await
    }

    /// Cancellation is observation-local. Resource equality is checked before
    /// runtime admission, proof signing or I/O; saved data cannot redirect a
    /// credential. The ordinary watcher owns all later lifetime/EOF checks.
    #[allow(clippy::too_many_arguments)]
    pub async fn resume_task_watch_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        checkpoint: &DpopTaskWatchCheckpoint,
        id_prefix: &str,
        policy: DpopTaskWatchPolicy,
        limits: DpopStreamLimits,
    ) -> Result<DpopTaskWaitOutcome, DpopTaskCheckpointError> {
        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            return Err(DpopTaskWatchError::from(DpopHttpError::Cancelled).into());
        }
        checkpoint.admit_resource(self.resource())?;
        Ok(self.watch_task_with_cancellation(
            cx, cancellation, credential, metadata, checkpoint.task_id.clone(),
            id_prefix, policy, limits,
        ).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};
    use fastmcp_protocol::ClientCapabilities;
    use fastmcp_protocol::dpop::DpopKey;
    use serde_json::json;
    use crate::http_auth::dpop::DpopSession;
    use crate::http_auth::dpop::native::DpopHttpPolicy;
    use crate::http_auth::dpop::native::core::DpopCoreError;
    use crate::http_auth::dpop::native::core::stream::DpopStreamError;

    fn resource() -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse("https://mcp.example/mcp?tenant=one").unwrap()
    }

    fn checkpoint() -> DpopTaskWatchCheckpoint {
        DpopTaskWatchCheckpoint::new(&resource(), TaskId::parse("task-secret").unwrap()).unwrap()
    }

    fn wire() -> serde_json::Value {
        serde_json::from_slice(&checkpoint().encode().unwrap()).unwrap()
    }

    pub(super) fn client() -> (DpopHttpClient, DpopCredential) {
        let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
        let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(), resource()).unwrap();
        let credential = session.admit_token_response(
            &issuer, 200,
            br#"{"access_token":"checkpoint-test-token","token_type":"DPoP","expires_in":60}"#,
            Instant::now(), Duration::from_secs(60),
        ).unwrap();
        (DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap(), credential)
    }

    #[test]
    fn checkpoint_round_trip_preserves_selection_without_execution_state() {
        let saved = checkpoint();
        let bytes = saved.encode().unwrap();
        let restored = DpopTaskWatchCheckpoint::decode(&bytes).unwrap();
        assert_eq!(restored.resource().as_str(), resource().as_str());
        assert_eq!(restored.task_id(), saved.task_id());
        assert_eq!(restored.encode().unwrap(), bytes);
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document.as_object().unwrap().len(), 5);
        for field in ["access_token", "privateKey", "requestState", "inputResponses", "status", "result"] {
            assert!(document.get(field).is_none());
        }
        let debug = format!("{restored:?}");
        assert!(!debug.contains("task-secret"));
        assert!(!debug.contains("tenant"));
        assert!(!debug.contains("mcp.example"));
    }

    #[test]
    fn closed_object_refuses_duplicates_arrays_unknown_state_and_trailing_data() {
        let good = checkpoint().encode().unwrap();
        let prefix = &std::str::from_utf8(&good).unwrap()[..good.len() - 1];
        for suffix in [
            r#", "taskId":"other"}"#,
            r#", "task\u0049d":"other"}"#,
            r#", "resource":"https://other.example/mcp"}"#,
            r#", "requestState":"saved-replay"}"#,
            r#", "inputResponses":[]}"#,
        ] {
            let bytes = format!("{prefix}{suffix}");
            assert!(matches!(DpopTaskWatchCheckpoint::decode(bytes.as_bytes()),
                Err(DpopTaskCheckpointError::InvalidDocument)));
        }
        let tuple = json!([CHECKPOINT_FORMAT, 1, FINAL_PROTOCOL_VERSION,
            resource().as_str(), "task-secret"]);
        for bytes in [serde_json::to_vec(&tuple).unwrap(), b"null".to_vec(),
            [good.as_slice(), b" {}"].concat(), Vec::new()] {
            assert!(matches!(DpopTaskWatchCheckpoint::decode(&bytes),
                Err(DpopTaskCheckpointError::InvalidDocument)));
        }
        assert!(DpopTaskWatchCheckpoint::decode(&good).is_ok());
    }

    #[test]
    fn format_protocol_and_canonical_https_resource_are_independently_enforced() {
        for (field, value) in [
            ("format", json!("fastmcp/task-watch")),
            ("version", json!(2)),
            ("protocolVersion", json!("2024-11-05")),
            ("resource", json!("http://mcp.example/mcp?tenant=one")),
            ("resource", json!("HTTPS://MCP.EXAMPLE/mcp?tenant=one")),
            ("resource", json!("file:///tmp/socket")),
            ("taskId", json!("")),
            ("taskId", json!("a".repeat(1025))),
        ] {
            let mut document = wire();
            document[field] = value;
            assert!(DpopTaskWatchCheckpoint::decode(&serde_json::to_vec(&document).unwrap()).is_err(),
                "changed {field} must be refused");
        }
        assert!(DpopTaskWatchCheckpoint::decode(&serde_json::to_vec(&wire()).unwrap()).is_ok());
        assert!(matches!(DpopTaskWatchCheckpoint::new(
            &CanonicalHttpUrl::parse("http://mcp.example/mcp").unwrap(),
            TaskId::parse("task-secret").unwrap(),
        ), Err(DpopTaskCheckpointError::InvalidResource)));
    }

    #[test]
    fn document_byte_bound_is_checked_before_parsing_and_accepts_exact_boundary() {
        let mut bytes = checkpoint().encode().unwrap();
        bytes.resize(MAX_DPOP_TASK_CHECKPOINT_BYTES, b' ');
        assert!(DpopTaskWatchCheckpoint::decode(&bytes).is_ok());
        bytes.push(b' ');
        assert!(matches!(DpopTaskWatchCheckpoint::decode(&bytes),
            Err(DpopTaskCheckpointError::TooLarge)));
        assert!(matches!(DpopTaskWatchCheckpoint::decode(&vec![b'x'; MAX_DPOP_TASK_CHECKPOINT_BYTES + 1]),
            Err(DpopTaskCheckpointError::TooLarge)));
    }

    #[test]
    fn resource_admission_matches_the_entire_endpoint_not_just_origin() {
        let saved = checkpoint();
        for url in ["https://other.example/mcp?tenant=one", "https://mcp.example/other?tenant=one",
            "https://mcp.example/mcp?tenant=two", "https://mcp.example:8443/mcp?tenant=one"] {
            let other = CanonicalHttpUrl::parse(url).unwrap();
            assert!(matches!(saved.admit_resource(&other), Err(DpopTaskCheckpointError::ResourceMismatch)));
        }
        assert!(saved.admit_resource(&resource()).is_ok());
        assert_eq!(saved.task_id(), &TaskId::parse("task-secret").unwrap());
    }

    #[test]
    fn public_restore_refuses_foreign_resource_before_runtime_admission() {
        let (mut client, credential) = client();
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        for matches in [false, true] {
            let endpoint = if matches { resource() } else {
                CanonicalHttpUrl::parse("https://mcp.example/mcp?tenant=two").unwrap()
            };
            let saved = DpopTaskWatchCheckpoint::new(&endpoint, TaskId::parse("task-secret").unwrap()).unwrap();
            let mut future = Box::pin(client.resume_task_watch_with_cancellation(
                &cx, &cancellation, &credential, FinalRequestMeta::new(ClientCapabilities::default()),
                &saved, "restored", DpopTaskWatchPolicy::default(), DpopStreamLimits::default(),
            ));
            let result = future.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            if matches {
                assert!(matches!(result, Poll::Ready(Err(DpopTaskCheckpointError::Watch(
                    DpopTaskWatchError::Stream(DpopStreamError::Core(DpopCoreError::Transport(
                        DpopHttpError::RuntimeUnavailable))))))));
            } else {
                assert!(matches!(result, Poll::Ready(Err(DpopTaskCheckpointError::ResourceMismatch))));
            }
            drop(future);
            assert!(!client.revocation_handle().is_revoked());
        }
    }

    #[test]
    fn both_restore_entrypoints_preserve_precancellation_and_reusable_login() {
        for cancel_caller in [false, true] {
            let (mut client, credential) = client();
            let saved = client.task_watch_checkpoint(TaskId::parse("task-secret").unwrap()).unwrap();
            let cx = Cx::for_testing();
            let cancellation = McpRequestCancellation::new();
            if cancel_caller { cx.set_cancel_requested(true); } else { cancellation.cancel(); }
            let mut future = Box::pin(client.resume_task_watch_with_cancellation(
                &cx, &cancellation, &credential, FinalRequestMeta::new(ClientCapabilities::default()),
                &saved, "", DpopTaskWatchPolicy::default(), DpopStreamLimits::default(),
            ));
            assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(DpopTaskCheckpointError::Watch(DpopTaskWatchError::Stream(
                    DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled))))))));
            drop(future);
            cx.set_cancel_requested(true);
            let mut future = Box::pin(client.resume_task_watch(
                &cx, &credential, FinalRequestMeta::new(ClientCapabilities::default()), &saved,
                "", DpopTaskWatchPolicy::default(), DpopStreamLimits::default(),
            ));
            assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(DpopTaskCheckpointError::Watch(DpopTaskWatchError::Stream(
                    DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled))))))));
            drop(future);
            assert!(!client.revocation_handle().is_revoked());
            assert!(saved.admit_resource(client.resource()).is_ok());
        }
    }
}
