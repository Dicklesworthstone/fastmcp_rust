//! Task snapshots joined to a live, acknowledged subscription.
//!
//! The second snapshot, after acknowledgement, closes the gap between the
//! initial tasks/get and listener admission. Events trigger reconciliation;
//! they are not used to roll a newer snapshot back to an older task state.

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::tasks_extension::task_subscription_ids;
use fastmcp_protocol::{RequestId, SubscriptionFilter};

use super::super::{
    MAX_TASK_RESPONSE_BYTES, ManagedHttpClient, ManagedHttpClientError, TaskCall, TaskResult,
    checkpoint, task_sse_limits,
};
use super::{EventBudget, MAX_NOTIFICATIONS, MAX_PAYLOAD_BYTES, refusal};
use crate::http_executor::ModernHttpSubscriptionListenEvent;
use crate::{
    ClientHttpConnectionError, FinalGetTaskResult, FinalTask, FinalTaskId, HttpClient,
    HttpClientError,
};

pub(in super::super::super) struct WatchRequest {
    task_id: FinalTaskId,
    budget: EventBudget,
}

fn require_watched_task(
    filter: &SubscriptionFilter,
    task_id: &FinalTaskId,
) -> Result<(), HttpClientError> {
    let accepted = task_subscription_ids(filter)
        .map_err(|_| refusal("Invalid managed task watch acknowledgement"))?;
    if accepted.is_some_and(|ids| ids.iter().any(|id| id == task_id)) {
        Ok(())
    } else {
        Err(refusal(
            "Managed task watch did not acknowledge the requested task",
        ))
    }
}

impl WatchRequest {
    fn new(
        task_id: FinalTaskId,
        max_notifications: usize,
        max_payload_bytes: usize,
    ) -> Result<Self, ManagedHttpClientError> {
        if !(1..=MAX_NOTIFICATIONS).contains(&max_notifications)
            || !(1..=MAX_PAYLOAD_BYTES).contains(&max_payload_bytes)
        {
            return Err(ManagedHttpClientError::InvalidPolicy);
        }
        Ok(Self {
            task_id,
            budget: EventBudget {
                notifications: max_notifications,
                remaining_bytes: max_payload_bytes,
            },
        })
    }

    async fn snapshot(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        client: &mut HttpClient,
        request_id: RequestId,
    ) -> Result<FinalGetTaskResult, HttpClientError> {
        // Give BOTH managed guards a turn before another POST. An earlier I/O
        // poll can finish after logout/expiry even with an otherwise live Cx.
        asupersync::runtime::yield_now().await;
        checkpoint(cx, cancellation)?;
        if self.budget.remaining_bytes == 0 {
            return Err(refusal("Managed task watch payload limit exceeded"));
        }
        // The native limit counts the whole response, including its JSON-RPC
        // envelope. The aggregate budget below counts the typed payload only;
        // using its remainder as a wire limit rejects an exact-fitting payload.
        let result = client
            .connection
            .get_task_final(cx, request_id, self.task_id.clone(), MAX_TASK_RESPONSE_BYTES)
            .await
            .map_err(HttpClientError::Connection)?;
        // Count snapshot bytes too, not just stream notifications. No second
        // representation is retained by the shared counting sink.
        self.budget.charge(&result, false)?;
        asupersync::runtime::yield_now().await;
        checkpoint(cx, cancellation)?;
        Ok(result)
    }

    pub(in super::super) async fn dispatch(
        mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        client: &mut HttpClient,
        request_id: RequestId,
    ) -> Result<TaskResult, HttpClientError> {
        let first = Box::pin(self.snapshot(cx, cancellation, client, request_id)).await?;
        if !matches!(&first.task, FinalTask::Working(_)) {
            return Ok(TaskResult::Get(Box::new(first)));
        }
        drop(first);

        let mut filter = SubscriptionFilter::default();
        super::set_task_subscription_ids(&mut filter, vec![self.task_id.clone()])
            .map_err(|_| refusal("Invalid managed task watch filter"))?;
        if self.budget.remaining_bytes == 0 {
            return Err(refusal("Managed task watch payload limit exceeded"));
        }
        // Frame overhead is bounded independently of admitted event payloads.
        let limits = task_sse_limits()?;
        let listen_id = client.next_request_id()?;
        let mut listener = client
            .connection
            .open_subscriptions_listener(cx, listen_id, filter, limits)
            .await
            .map_err(HttpClientError::Connection)?;
        let mut acknowledged = false;
        loop {
            // No periodic tasks/get while quiet; the native stream and the
            // original managed operation retain their finite idle/deadline bounds.
            asupersync::runtime::yield_now().await;
            checkpoint(cx, cancellation)?;
            let event = listener
                .next_event(cx)
                .await
                .map_err(|error| {
                    HttpClientError::Connection(ClientHttpConnectionError::SubscriptionsListen(
                        error,
                    ))
                })?
                .ok_or_else(|| {
                    refusal("Managed task watch ended without a terminal result")
                })?;
            self.budget.admit(&event)?;
            let ended = match &event {
                ModernHttpSubscriptionListenEvent::Acknowledged { accepted_filter }
                    if !acknowledged =>
                {
                    require_watched_task(accepted_filter, &self.task_id)?;
                    acknowledged = true;
                    false
                }
                ModernHttpSubscriptionListenEvent::TaskNotification(notification)
                    if acknowledged
                        && notification.params.task.base().task_id == self.task_id =>
                {
                    false
                }
                ModernHttpSubscriptionListenEvent::Terminal { .. } if acknowledged => true,
                _ => return Err(refusal("Unexpected event on a managed task watch")),
            };
            drop(event);

            // Always reconcile after ACK, even without a status notification:
            // completion can precede listener admission and never emit one here.
            // Reconcile notifications as hints, so a buffered old Working event
            // cannot overwrite a later input-required or terminal snapshot.
            let request_id = client.next_request_id()?;
            let current = Box::pin(self.snapshot(cx, cancellation, client, request_id)).await?;
            if !matches!(&current.task, FinalTask::Working(_)) {
                listener.cancel();
                return Ok(TaskResult::Get(Box::new(current)));
            }
            drop(current);
            if ended {
                // Stream completion is not task completion. The final snapshot
                // closes that last race without reconnecting or inventing success.
                return Err(refusal(
                    "Managed task watch ended while the task is still working",
                ));
            }
        }
    }
}

impl ManagedHttpClient {
    /// Watches one task until it needs input, completes, fails or is cancelled.
    ///
    /// Fetches a snapshot first. If it is Working, opens one Tasks subscription
    /// and fetches AGAIN after its acknowledgement. This second fetch catches
    /// completion between the first snapshot and listener admission, even when
    /// no notification is emitted. Subsequent admitted notifications trigger
    /// fresh snapshots; buffered notifications never overwrite newer state.
    /// No periodic polling is performed while the subscription is quiet.
    ///
    /// A successful result is never Working, but is not necessarily a successful
    /// task: inspect `result.task` for InputRequired, Completed, Failed or Cancelled.
    /// A subscription terminal triggers one last snapshot; if it is still Working,
    /// the watch fails. Missing acknowledgement of the requested task, premature
    /// EOF, invalid input, and exhausted limits are also errors, not partial success.
    ///
    /// One original credential and the client's finite operation deadline cover
    /// acquisition, discovery, every snapshot and the entire listen. No refresh,
    /// reconnect, failed-request retry, task update or remote cancellation is
    /// performed inside the watch. Cancellation or abandonment drops both owned
    /// responses and discards the connection without closing the shared login.
    /// A successful watch closes its local listen and may reuse discovery later.
    ///
    /// Requires `with_tasks`, 1..=1024 notifications INCLUDING the acknowledgement,
    /// and 1..=128 MiB of aggregate encoded snapshot and event payloads. Terminals
    /// and snapshots consume bytes, not notification slots. Each native response
    /// retains its separate 8 MiB ceiling. Limits refuse before acquiring a grant.
    /// The initial snapshot, one subscription, and at most one reconciliation per
    /// admitted event are sent, all with distinct request IDs. No history is kept.
    pub async fn watch_task_final(
        &mut self,
        cx: &Cx,
        task_id: FinalTaskId,
        max_notifications: usize,
        max_payload_bytes: usize,
    ) -> Result<FinalGetTaskResult, ManagedHttpClientError> {
        self.watch_task_final_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            task_id,
            max_notifications,
            max_payload_bytes,
        )
        .await
    }

    /// Watches with request-local cancellation, leaving sibling login users live.
    pub async fn watch_task_final_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
        max_notifications: usize,
        max_payload_bytes: usize,
    ) -> Result<FinalGetTaskResult, ManagedHttpClientError> {
        self.admit_tasks(cx, cancellation)?;
        let request = WatchRequest::new(task_id, max_notifications, max_payload_bytes)?;
        match self
            .perform_task(cx, cancellation, TaskCall::Watch(request))
            .await?
        {
            TaskResult::Get(result) => Ok(*result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn id() -> FinalTaskId {
        FinalTaskId::parse("watched-task").unwrap()
    }

    #[test]
    fn watch_bounds_admit_the_ceiling_but_never_clamp_invalid_limits() {
        assert!(WatchRequest::new(id(), MAX_NOTIFICATIONS, MAX_PAYLOAD_BYTES).is_ok());
        for (count, bytes) in [
            (0, 1),
            (1, 0),
            (MAX_NOTIFICATIONS + 1, 1),
            (1, MAX_PAYLOAD_BYTES + 1),
            (usize::MAX, usize::MAX),
        ] {
            assert!(matches!(
                WatchRequest::new(id(), count, bytes),
                Err(ManagedHttpClientError::InvalidPolicy)
            ));
        }
    }

    #[test]
    fn empty_or_absent_accepted_task_selection_cannot_establish_a_watch() {
        for ids in [None, Some(vec![]), Some(vec![id()])] {
            let accepted = ids.as_ref().is_some_and(|ids| !ids.is_empty());
            let mut filter = SubscriptionFilter::default();
            if let Some(ids) = ids {
                super::super::set_task_subscription_ids(&mut filter, ids).unwrap();
            }
            let before = serde_json::to_value(&filter).unwrap();
            assert_eq!(require_watched_task(&filter, &id()).is_ok(), accepted);
            assert_eq!(serde_json::to_value(filter).unwrap(), before);
        }
    }

    #[test]
    fn acknowledgement_checks_exact_task_identity_without_reflecting_it() {
        let mut filter = SubscriptionFilter::default();
        super::super::set_task_subscription_ids(&mut filter, vec![id()]).unwrap();
        require_watched_task(&filter, &id()).unwrap();
        let other = FinalTaskId::parse("private-other-task").unwrap();
        let error = require_watched_task(&filter, &other).unwrap_err();
        assert!(!format!("{error:?}").contains("private-other-task"));
        require_watched_task(&filter, &id()).unwrap();
    }

    #[test]
    fn snapshot_bytes_share_event_budget_without_spending_notification_slots() {
        let value: FinalGetTaskResult = serde_json::from_value(json!({
            "resultType":"complete", "taskId":"watched-task", "status":"working",
            "createdAt":"2026-07-28T12:00:00.000Z",
            "lastUpdatedAt":"2026-07-28T12:00:00.000Z", "ttlMs":60000
        }))
        .unwrap();
        let bytes = serde_json::to_vec(&value).unwrap().len();
        for (remaining, fits) in [(bytes, true), (bytes - 1, false)] {
            let mut watch = WatchRequest::new(id(), 1, remaining).unwrap();
            assert_eq!(watch.budget.charge(&value, false).is_ok(), fits);
            assert_eq!(watch.budget.notifications, 1);
            assert_eq!(
                watch.budget.remaining_bytes,
                if fits { 0 } else { remaining }
            );
        }
    }
}
