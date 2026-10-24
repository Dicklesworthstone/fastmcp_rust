//! Fresh DPoP reconciliation of protected, owner-bound Task resume records.
//!
//! Reuses the existing control-only record and conditional storage change.
//! The host opens protected records in its own blocking lane and supplies its
//! CURRENT verified owner/profile binding, independently of stored bytes. A
//! record cannot select a login, transport root, endpoint or DPoP signing key.
//! Neither the stored status nor a Task ID is proof of remote authorization.

#[cfg(all(test, feature = "native-tls-roots"))]
mod tls;

use std::fmt;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::tasks_extension::GetTaskResult;
use fastmcp_protocol::{FinalRequestMeta, ServerNotification};

use super::{DpopTaskCheckpointError, DpopTaskWatchCheckpoint};
use super::super::{DpopTaskWatchError, DpopTaskWatchPolicy, WatchState};
use crate::http_auth::dpop::native::{
    DpopCredential, DpopHttpClient, DpopHttpError, WaitBounds, check_live,
};
use crate::http_auth::dpop::native::core::DpopCoreError;
use crate::http_auth::dpop::native::core::stream::{DpopStreamError, DpopStreamLimits};
use crate::http_auth::dpop::native::core::tasks::ManagedTaskEvent;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::client::resume_read_deadline;
use crate::http_auth::rpc::ManagedCoreError;

pub use crate::http_auth::managed::tasks::watch::checkpoint::resume::{
    TaskResumeBinding, TaskResumeError, TaskResumeRecord,
};
pub use crate::http_auth::managed::tasks::watch::checkpoint::resume::client::lifecycle::TaskResumeChange;

/// One authoritative response, separate from its payload-free storage change.
/// This is neither Clone nor serializable. Debug omits all peer data.
///
/// Active controls can be conditionally persisted through `change().apply()`
/// on Linux or the host's own provider. A terminal change removes exactly the
/// previous version: handle or durably save its result BEFORE applying it.
/// A crash before acknowledgement can redeliver a terminal; this is not an
/// exactly-once delivery protocol or durable server-side execution.
pub struct DpopTaskResumeSnapshot {
    snapshot: Box<GetTaskResult>,
    change: TaskResumeChange,
    selection: Option<DpopTaskWatchCheckpoint>,
}

impl DpopTaskResumeSnapshot {
    pub fn snapshot(&self) -> &GetTaskResult { &self.snapshot }
    pub fn change(&self) -> &TaskResumeChange { &self.change }
    /// Only active Tasks have a selection. Starting a watch is a separate host
    /// decision with fresh authentication and finite limits, not old authority.
    pub fn selection(&self) -> Option<&DpopTaskWatchCheckpoint> { self.selection.as_ref() }
    pub fn into_parts(self) -> (Box<GetTaskResult>, TaskResumeChange, Option<DpopTaskWatchCheckpoint>) {
        (self.snapshot, self.change, self.selection)
    }
}

impl fmt::Debug for DpopTaskResumeSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopTaskResumeSnapshot")
            .field("terminal", &self.selection.is_none())
            .finish_non_exhaustive()
    }
}

/// Local unavailable records and HTTP 401/403/404 intentionally share one
/// outcome. Transport and observer failures remain typed, without peer text.
#[derive(Debug)]
pub enum DpopTaskResumeError {
    Resume(TaskResumeError),
    Checkpoint(DpopTaskCheckpointError),
}
impl fmt::Display for DpopTaskResumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resume(error) => error.fmt(f),
            Self::Checkpoint(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for DpopTaskResumeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resume(error) => Some(error),
            Self::Checkpoint(error) => Some(error),
        }
    }
}
impl From<TaskResumeError> for DpopTaskResumeError {
    fn from(error: TaskResumeError) -> Self { Self::Resume(error) }
}
impl From<DpopTaskCheckpointError> for DpopTaskResumeError {
    fn from(error: DpopTaskCheckpointError) -> Self { Self::Checkpoint(error) }
}
impl From<DpopTaskWatchError> for DpopTaskResumeError {
    fn from(error: DpopTaskWatchError) -> Self { Self::Checkpoint(error.into()) }
}
impl From<DpopHttpError> for DpopTaskResumeError {
    fn from(error: DpopHttpError) -> Self { DpopTaskWatchError::from(error).into() }
}

fn classify(error: DpopStreamError) -> DpopTaskResumeError {
    match error {
        DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::HttpStatus {
            status: 401 | 403 | 404,
        })) => TaskResumeError::Unavailable.into(),
        error => DpopTaskWatchError::from(error).into(),
    }
}

// The retained deadline is anchored once, before runtime admission. The native
// owner still wins ties and keeps its precise credential/cancellation error.
fn retained_bounds(owner: WaitBounds, retention: Time) -> WaitBounds {
    if retention < owner.deadline {
        WaitBounds { deadline: retention, terminal: DpopHttpError::TimedOut }
    } else { owner }
}

fn reconciled(
    cx: &Cx, current: &TaskResumeBinding, previous: &TaskResumeRecord,
    snapshot: Box<GetTaskResult>,
) -> Result<DpopTaskResumeSnapshot, DpopTaskResumeError> {
    // The shared comparator enforces ID, creation instant, immutable TTL,
    // monotonic update time, status consistency and ORIGINAL host retention.
    let change = TaskResumeChange::from_snapshot(cx, current, previous, &snapshot.task)?;
    let selection = change.replacement().map(|record| {
        DpopTaskWatchCheckpoint::new(current.resource(), record.task_id().clone())
    }).transpose()?;
    Ok(DpopTaskResumeSnapshot { snapshot, change, selection })
}

impl DpopHttpClient {
    /// Reconcile one protected resume record through this explicitly chosen
    /// DPoP login. Validated notifications consume the budget but are discarded.
    /// Open/persist records separately in the host's owned blocking lane.
    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_task_resume(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
        credential: &DpopCredential, metadata: FinalRequestMeta,
        current: &TaskResumeBinding, record: &TaskResumeRecord,
        id_prefix: &str, limits: DpopStreamLimits,
    ) -> Result<DpopTaskResumeSnapshot, DpopTaskResumeError> {
        self.reconcile_task_resume_with_events(
            cx, cancellation, credential, metadata, current, record,
            id_prefix, limits, |_| true,
        ).await
    }

    /// Fresh authenticated discovery/get, bounded by the original credential,
    /// caller, native/core timeout AND the saved record's remaining retention.
    /// The host must associate current verified owner/profile facts with the
    /// supplied login; none are inferred from a token, record or response.
    /// Wrong owner/profile/endpoint and expired records fail before signing or
    /// I/O. Wall-clock rollback cannot extend an already admitted operation.
    /// Cross-process wall-clock integrity remains the host's responsibility.
    ///
    /// JSON/SSE replies require clean HTTP EOF. Application data and metadata
    /// are preserved only in the returned snapshot, never in the storage
    /// change. Regressed or conflicting controls fail without replacing the
    /// saved record. An active replacement retains the original expiry, not a
    /// new full retention window. Terminal cleanup is an explicit host action
    /// AFTER handling the result, never a consequence of a failed read.
    ///
    /// Notifications arrive incrementally. Observers must be brief/nonblocking;
    /// refusal or panic stops this read. Cancellation, revocation and deadlines
    /// remain effective through decoding/publication. Dropping the future owns
    /// no worker and leaves storage untouched. No renewal, creation, update,
    /// input resolution, remote cancellation, retry or subscription is performed.
    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_task_resume_with_events<N>(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
        credential: &DpopCredential, metadata: FinalRequestMeta,
        current: &TaskResumeBinding, record: &TaskResumeRecord,
        id_prefix: &str, limits: DpopStreamLimits, mut notify: N,
    ) -> Result<DpopTaskResumeSnapshot, DpopTaskResumeError>
    where N: FnMut(&ServerNotification) -> bool,
    {
        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            return Err(DpopHttpError::Cancelled.into());
        }
        let retention = resume_read_deadline(cx, current, record, self.resource().as_str())?;
        let mut state = WatchState::new(id_prefix, DpopTaskWatchPolicy::new(1)?, limits)?;
        let (operation, limits) = state.snapshot_request(record.task_id())?;
        let owner = WaitBounds::new(cx, self.policy.timeout.min(limits.core.timeout()), credential)?;
        let bounds = retained_bounds(owner, retention);
        check_live(cx, cancellation, &self.session, credential, owner)?;
        if cx.now() >= retention { return Err(TaskResumeError::Unavailable.into()); }
        record.admit(cx, current)?;
        let response = self.request_task_stream_with_bounds(
            cx, cancellation, credential, metadata, operation, limits, bounds, &mut notify,
        ).await;
        // Stop/revoke/owner timeout outranks unavailable and any peer error.
        // Checking ORIGINAL owner bounds lets retention expiry stay unavailable.
        check_live(cx, cancellation, &self.session, credential, owner)?;
        if cx.now() >= retention { return Err(TaskResumeError::Unavailable.into()); }
        record.admit(cx, current)?;
        let ManagedTaskEvent::Snapshot(snapshot) = response.map_err(classify)?.result else {
            return Err(TaskResumeError::InvalidRecord.into());
        };
        let result = reconciled(cx, current, record, snapshot);
        check_live(cx, cancellation, &self.session, credential, owner)?;
        if cx.now() >= retention { return Err(TaskResumeError::Unavailable.into()); }
        record.admit(cx, current)?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;
    use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
    use fastmcp_protocol::ClientCapabilities;
    use serde_json::json;

    pub(super) fn binding(subject: &str, resource: &str) -> TaskResumeBinding {
        let owner = DurableOwnerKey::derive(&PartitionDescriptor::from_verified_facts(
            "fixture", 1, "https://issuer.example", resource, "tenant", subject,
            "client", 1, 1, &[b"bound-resource".as_slice()],
        ).unwrap(), 1).unwrap();
        TaskResumeBinding::from_verified_owner(
            fastmcp_core::CanonicalHttpUrl::parse(resource).unwrap(), "fixture", &owner,
            [2; 32], [3; 32], [4; 32],
        ).unwrap()
    }

    pub(super) fn snapshot(status: &str, second: u8) -> Box<GetTaskResult> {
        let mut value = json!({"resultType":"complete", "taskId":"task-secret", "status":status,
            "createdAt":"2020-01-01T00:00:00Z",
            "lastUpdatedAt":format!("2020-01-01T00:00:0{second}Z"),
            "ttlMs":null, "pollIntervalMs":1000,
            "statusMessage":"SECRET-STATUS", "_meta":{"private":"SECRET-METADATA"}});
        if status == "input_required" {
            value["inputRequests"] = json!({"SECRET-INPUT":{"method":"roots/list"}});
        }
        Box::new(serde_json::from_value(value).unwrap())
    }

    pub(super) fn record(cx: &Cx, binding: &TaskResumeBinding) -> TaskResumeRecord {
        TaskResumeRecord::capture(cx, binding, &snapshot("working", 1).task, Duration::from_secs(3600)).unwrap()
    }

    #[test]
    fn protected_reconciliation_preserves_original_retention_and_excludes_payloads() {
        let cx = Cx::for_testing();
        let binding = binding("owner", "https://mcp.example/mcp?tenant=one");
        let previous = record(&cx, &binding);
        let before = previous.encode().unwrap();
        let observed = snapshot("input_required", 2);
        let expected = serde_json::to_value(&observed).unwrap();
        let current = reconciled(&cx, &binding, &previous, observed).unwrap();
        assert_eq!(serde_json::to_value(current.snapshot()).unwrap(), expected);
        assert_eq!(current.change().previous(), &previous);
        let next = current.change().replacement().unwrap();
        assert_eq!(next.key(), previous.key());
        let encoded = next.encode().unwrap();
        assert_eq!(&encoded[encoded.len()-16..], &before[before.len()-16..], "retention must not renew");
        assert!(!encoded.windows(6).any(|bytes| bytes == b"SECRET"));
        assert_eq!(current.selection().unwrap().task_id(), previous.task_id());
        assert!(!format!("{current:?}").contains("SECRET"));
        assert!(!format!("{current:?}").contains("task-secret"));
        assert_eq!(previous.encode().unwrap(), before);
    }

    #[test]
    fn protected_reconciliation_requires_explicit_exact_terminal_cleanup() {
        let cx = Cx::for_testing();
        let binding = binding("owner", "https://mcp.example/mcp");
        let previous = record(&cx, &binding);
        let before = previous.encode().unwrap();
        let result = reconciled(&cx, &binding, &previous, snapshot("cancelled", 2)).unwrap();
        assert!(result.selection().is_none());
        assert!(result.change().replacement().is_none());
        assert_eq!(result.change().previous(), &previous);
        assert!(matches!(result.snapshot().task, fastmcp_protocol::tasks_extension::Task::Cancelled(_)));
        assert_eq!(previous.encode().unwrap(), before, "delivery does not retire the saved lookup");
    }

    #[test]
    fn changed_or_regressed_controls_cannot_replace_a_protected_record() {
        let cx = Cx::for_testing();
        let binding = binding("owner", "https://mcp.example/mcp");
        let previous = record(&cx, &binding);
        let before = previous.encode().unwrap();
        for dimension in 0..5 {
            let mut wire = serde_json::to_value(snapshot("working", 2)).unwrap();
            match dimension {
                0 => wire["taskId"] = json!("other"),
                1 => wire["createdAt"] = json!("2019-12-31T00:00:00Z"),
                2 => wire["ttlMs"] = json!(60_000),
                3 => wire["lastUpdatedAt"] = json!("2020-01-01T00:00:00Z"),
                _ => {
                    wire["lastUpdatedAt"] = json!("2020-01-01T00:00:01Z");
                    wire["pollIntervalMs"] = json!(2000);
                }
            }
            let result = reconciled(&cx, &binding, &previous, Box::new(serde_json::from_value(wire).unwrap()));
            assert!(matches!(result, Err(DpopTaskResumeError::Resume(
                TaskResumeError::StaleSnapshot | TaskResumeError::ConflictingSnapshot))));
            assert_eq!(previous.encode().unwrap(), before);
        }
        assert!(reconciled(&cx, &binding, &previous, snapshot("working", 2)).is_ok());
    }

    #[test]
    fn wrong_owner_endpoint_and_expiry_fail_before_runtime_admission() {
        let cx = Cx::for_testing();
        let (mut client, credential) = super::super::tests::client();
        let current = binding("owner", client.resource().as_str());
        let valid = record(&cx, &current);
        let owner = binding("other", client.resource().as_str());
        let endpoint = binding("owner", "https://mcp.example/mcp?tenant=other");
        let mut expired = valid.encode().unwrap();
        let n = expired.len();
        expired[n-16..].copy_from_slice(&1_577_836_810_000_000_000_i128.to_be_bytes());
        let expired = TaskResumeRecord::decode(&expired).unwrap();
        let cancellation = McpRequestCancellation::new();
        for (binding, saved, available) in [
            (&owner, &valid, false), (&endpoint, &valid, false),
            (&current, &expired, false), (&current, &valid, true),
        ] {
            let mut future = Box::pin(client.reconcile_task_resume(
                &cx, &cancellation, &credential,
                FinalRequestMeta::new(ClientCapabilities::default()), binding, saved,
                "protected", DpopStreamLimits::default(),
            ));
            let result = future.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            if available {
                assert!(matches!(result, Poll::Ready(Err(DpopTaskResumeError::Checkpoint(
                    DpopTaskCheckpointError::Watch(DpopTaskWatchError::Stream(DpopStreamError::Core(
                        DpopCoreError::Transport(DpopHttpError::RuntimeUnavailable)))))))));
            } else {
                assert!(matches!(result, Poll::Ready(Err(DpopTaskResumeError::Resume(TaskResumeError::Unavailable)))));
            }
            drop(future);
            assert!(!client.revocation_handle().is_revoked());
        }
    }

    #[test]
    fn retention_only_tightens_the_original_native_deadline_and_preserves_ties() {
        let origin = Cx::for_testing().now();
        let owner = WaitBounds {
            deadline: origin.saturating_add_nanos(100),
            terminal: DpopHttpError::Authorization(crate::http_auth::dpop::DpopClientError::CredentialUnavailable),
        };
        for offset in [50, 100, 150] {
            let bounds = retained_bounds(owner, origin.saturating_add_nanos(offset));
            assert_eq!(bounds.deadline, origin.saturating_add_nanos(offset.min(100)));
            assert_eq!(bounds.terminal, if offset < 100 { DpopHttpError::TimedOut } else { owner.terminal });
        }
    }

    #[test]
    fn unavailable_mapping_does_not_hide_transport_or_observer_failure() {
        for status in [401, 403, 404, 429, 500] {
            let error = classify(ManagedCoreError::HttpStatus { status }.into());
            assert_eq!(matches!(error, DpopTaskResumeError::Resume(TaskResumeError::Unavailable)),
                matches!(status, 401 | 403 | 404));
        }
        assert!(matches!(classify(DpopHttpError::TransportFailed.into()),
            DpopTaskResumeError::Checkpoint(DpopTaskCheckpointError::Watch(DpopTaskWatchError::Stream(
                DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::TransportFailed)))))));
        assert!(matches!(classify(DpopStreamError::ObserverStopped),
            DpopTaskResumeError::Checkpoint(DpopTaskCheckpointError::Watch(DpopTaskWatchError::Stream(
                DpopStreamError::ObserverStopped)))));
    }
}
