//! Incremental Tasks notifications without releasing managed credential custody.

use std::io::{self, Write};
use std::ops::ControlFlow;

use asupersync::Cx;
use fastmcp_core::{McpError, McpRequestCancellation};
use fastmcp_protocol::tasks_extension::{MAX_TASK_SUBSCRIPTION_IDS, set_task_subscription_ids};
use fastmcp_protocol::{
    CompleteResult, FinalSubscriptionsListenResult, RequestId, SubscriptionFilter,
    encode_complete_result,
};
use serde::Serialize;

use super::{
    ManagedHttpClient, ManagedHttpClientError, TaskCall, TaskResult, checkpoint, task_sse_limits,
};
use crate::http_executor::{ModernHttpSubscriptionListenEvent, ModernHttpSubscriptionTermination};
use crate::{ClientHttpConnectionError, FinalTaskId, HttpClient, HttpClientError};

pub(super) mod watch;

const MAX_NOTIFICATIONS: usize = 1_024;
const MAX_PAYLOAD_BYTES: usize = 128 * 1024 * 1024;

type Observer<'a> =
    &'a mut (dyn FnMut(&ModernHttpSubscriptionListenEvent) -> ControlFlow<()> + Send);

pub(in super::super) struct ListenRequest<'a> {
    filter: SubscriptionFilter,
    budget: EventBudget,
    observer: Observer<'a>,
}

fn refusal(message: &'static str) -> HttpClientError {
    HttpClientError::CoreResult(McpError::invalid_request(message))
}

// Counts encoded payloads without allocating a second representation or keeping
// event history. This is an application payload budget; native HTTP/SSE framing
// separately bounds raw frames, decoded expansion, pending events and idle time.
struct PayloadCounter {
    remaining: usize,
    written: usize,
}

impl Write for PayloadCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("managed Tasks payload limit"));
        }
        self.remaining -= bytes.len();
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct EventBudget {
    notifications: usize,
    remaining_bytes: usize,
}

impl EventBudget {
    fn charge(
        &mut self,
        value: &impl Serialize,
        notification: bool,
    ) -> Result<(), HttpClientError> {
        if notification && self.notifications == 0 {
            return Err(refusal(
                "Managed Tasks subscription notification limit exceeded",
            ));
        }
        let mut counter = PayloadCounter {
            remaining: self.remaining_bytes,
            written: 0,
        };
        serde_json::to_writer(&mut counter, value)
            .map_err(|_| refusal("Managed Tasks subscription payload limit exceeded"))?;
        // Admission is atomic: a refused event neither consumes a partial
        // allowance nor reaches the observer.
        self.remaining_bytes -= counter.written;
        if notification {
            self.notifications -= 1;
        }
        Ok(())
    }

    fn admit(&mut self, event: &ModernHttpSubscriptionListenEvent) -> Result<(), HttpClientError> {
        match event {
            ModernHttpSubscriptionListenEvent::Acknowledged { accepted_filter } => {
                self.charge(accepted_filter, true)
            }
            ModernHttpSubscriptionListenEvent::TaskNotification(notification) => {
                self.charge(notification, true)
            }
            ModernHttpSubscriptionListenEvent::Terminal { result, .. } => {
                self.charge_terminal(result)
            }
            ModernHttpSubscriptionListenEvent::Cancelled { params, .. } => {
                self.charge(params, false)
            }
            ModernHttpSubscriptionListenEvent::Notification(_) => {
                // This facade requests taskIds only, never catalog categories.
                Err(refusal("Non-Tasks event on a managed Tasks subscription"))
            }
        }
    }

    // A complete result is encoded by the result algebra, not serde.
    // `subscriptions/listen` owns no method members, so its payload is the
    // discriminator, the common metadata and any inert open siblings. A
    // terminal is not a notification and never consumes that allowance.
    fn charge_terminal(
        &mut self,
        result: &CompleteResult<FinalSubscriptionsListenResult>,
    ) -> Result<(), HttpClientError> {
        let encoded = encode_complete_result(&result.meta, Vec::new(), &[], &result.extras)
            .map_err(|_| refusal("Managed Tasks subscription terminal result is invalid"))?;
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(encoded.len())
            .ok_or_else(|| refusal("Managed Tasks subscription payload limit exceeded"))?;
        Ok(())
    }
}

impl<'a> ListenRequest<'a> {
    fn new(
        task_ids: Vec<FinalTaskId>,
        max_notifications: usize,
        max_payload_bytes: usize,
        observer: Observer<'a>,
    ) -> Result<Self, ManagedHttpClientError> {
        if !(1..=MAX_TASK_SUBSCRIPTION_IDS).contains(&task_ids.len())
            || !(1..=MAX_NOTIFICATIONS).contains(&max_notifications)
            || !(1..=MAX_PAYLOAD_BYTES).contains(&max_payload_bytes)
        {
            return Err(ManagedHttpClientError::InvalidPolicy);
        }
        let mut filter = SubscriptionFilter::default();
        set_task_subscription_ids(&mut filter, task_ids)
            .map_err(|_| ManagedHttpClientError::InvalidPolicy)?;
        Ok(Self {
            filter,
            budget: EventBudget {
                notifications: max_notifications,
                remaining_bytes: max_payload_bytes,
            },
            observer,
        })
    }

    pub(super) async fn dispatch(
        mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        client: &mut HttpClient,
        request_id: RequestId,
    ) -> Result<TaskResult, HttpClientError> {
        // JSON-RPC correlation fields and SSE framing are not application
        // payload. Keep their native ceiling independent so an exact-fitting
        // accepted filter or terminal can reach the typed budget below.
        let limits = task_sse_limits()?;
        let mut listener = client
            .connection
            .open_subscriptions_listener(cx, request_id, self.filter, limits)
            .await
            .map_err(HttpClientError::Connection)?;
        loop {
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
                    refusal("Managed Tasks subscription ended without a terminal result")
                })?;
            self.budget.admit(&event)?;

            // An I/O poll can finish after the credential expired or was revoked.
            // Return to BOTH enclosing managed guards before publishing an event
            // to application code, even when all peer frames are already buffered.
            // This also bounds application callbacks to one per executor turn.
            asupersync::runtime::yield_now().await;
            checkpoint(cx, cancellation)?;
            match event {
                ModernHttpSubscriptionListenEvent::Terminal { result, .. } => {
                    return Ok(TaskResult::Listen(Some(Box::new(
                        ModernHttpSubscriptionTermination::Complete(result),
                    ))));
                }
                ModernHttpSubscriptionListenEvent::Cancelled { params, .. } => {
                    return Ok(TaskResult::Listen(Some(Box::new(
                        ModernHttpSubscriptionTermination::Cancelled(params),
                    ))));
                }
                _ => {}
            }
            let decision = (self.observer)(&event);
            checkpoint(cx, cancellation)?;
            if decision.is_break() {
                // Local stop is NOT a peer complete result and never cancels a
                // remote task. The outer guards still check this ready return.
                listener.cancel();
                return Ok(TaskResult::Listen(None));
            }
            // A callback may close the session or revoke the original token.
            // Do not read a coalesced next event before its owner observes that.
            asupersync::runtime::yield_now().await;
        }
    }
}

impl ManagedHttpClient {
    /// Delivers live status changes for an explicit set of official Tasks.
    ///
    /// Requires `with_tasks` and bilateral Tasks discovery. Sends one
    /// `subscriptions/listen` POST, never `tasks/get`, reconnects, refreshes or
    /// cancellation POSTs during the listen. Exact ID spelling, order and
    /// duplicates are retained in the requested filter. The server may accept a
    /// subset, reported by the first `Acknowledged` event. Later task events
    /// must match that accepted set and the subscription's correlation ID.
    ///
    /// The observer sees the acknowledgement and each task notification in wire
    /// order, including exact task result payloads. Return `ControlFlow::Break(())`
    /// to stop locally. `Ok(None)` means this explicit local stop; `Ok(Some(_))`
    /// is the native listener's correlated complete or cancellation terminal.
    /// Peer cancellation remains distinct from local stop. A terminal
    /// event is returned, not passed to the observer. EOF without a terminal,
    /// malformed input and limits exceeded are errors, not partial success.
    /// This retains the native listener's terminal-admission semantics; it does
    /// not add a separate trailing-body/EOF verification after that terminal.
    ///
    /// The finite client operation timeout and ORIGINAL credential lifetime
    /// cover discovery, all events, idle time and observer calls. Both managed
    /// guards regain control before and after each callback; session closure or
    /// revocation cannot publish another already-buffered event. No stream or
    /// raw client escapes the guard. A failed/abandoned listen retires the local
    /// connection. A normal local stop may retain it for a later explicit call.
    /// Independently constructed clients can share the same managed login.
    ///
    /// Accepts 1..=128 task IDs and 1..=1024 notifications (including the ack).
    /// `max_payload_bytes` is 1..=128 MiB of aggregate serialized accepted-filter,
    /// task-notification and terminal-result payloads, not a raw-wire count.
    /// Native framing has an additional 8 MiB ceiling and 4096 data lines per
    /// event. No event history is retained here. Invalid limits refuse before
    /// acquisition or I/O. Observers must not block; their already-performed
    /// side effects cannot be undone if a later event or the operation fails.
    pub async fn listen_task_events(
        &mut self,
        cx: &Cx,
        task_ids: Vec<FinalTaskId>,
        max_notifications: usize,
        max_payload_bytes: usize,
        observer: &mut (dyn FnMut(&ModernHttpSubscriptionListenEvent) -> ControlFlow<()> + Send),
    ) -> Result<Option<ModernHttpSubscriptionTermination>, ManagedHttpClientError>
    {
        self.listen_task_events_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            task_ids,
            max_notifications,
            max_payload_bytes,
            observer,
        )
        .await
    }

    /// The live Tasks listen with an independent caller cancellation domain.
    /// Cancellation closes only this HTTP exchange, not the login or any task.
    #[allow(clippy::too_many_arguments)]
    pub async fn listen_task_events_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_ids: Vec<FinalTaskId>,
        max_notifications: usize,
        max_payload_bytes: usize,
        observer: &mut (dyn FnMut(&ModernHttpSubscriptionListenEvent) -> ControlFlow<()> + Send),
    ) -> Result<Option<ModernHttpSubscriptionTermination>, ManagedHttpClientError>
    {
        self.admit_tasks(cx, cancellation)?;
        let request = ListenRequest::new(task_ids, max_notifications, max_payload_bytes, observer)?;
        match self
            .perform_task(cx, cancellation, TaskCall::Listen(request))
            .await?
        {
            TaskResult::Listen(result) => Ok(result.map(|result| *result)),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn event_budget_accepts_exact_bytes_and_rolls_back_failed_admission() {
        let value = json!({"exact": "payload"});
        let length = serde_json::to_vec(&value).unwrap().len();
        let mut budget = EventBudget {
            notifications: 1,
            remaining_bytes: length,
        };
        budget.charge(&value, true).unwrap();
        assert_eq!(budget.remaining_bytes, 0);
        assert_eq!(budget.notifications, 0);
        assert!(budget.charge(&value, true).is_err());
        let mut insufficient = EventBudget {
            notifications: 2,
            remaining_bytes: length - 1,
        };
        assert!(insufficient.charge(&value, true).is_err());
        assert_eq!(insufficient.remaining_bytes, length - 1);
        assert_eq!(insufficient.notifications, 2);
    }

    #[test]
    fn acknowledgement_payload_budget_is_independent_of_its_wire_envelope() {
        let accepted_filter: SubscriptionFilter =
            serde_json::from_value(json!({"taskIds": ["task-1"]})).unwrap();
        let payload_bytes = serde_json::to_vec(&accepted_filter).unwrap().len();
        let envelope = json!({
            "jsonrpc": "2.0",
            "method": "notifications/subscriptions/acknowledged",
            "params": {
                "notifications": accepted_filter,
                "_meta": {"io.modelcontextprotocol/subscriptionId": 7}
            }
        });
        let wire = format!("data: {envelope}\n\n");
        assert!(wire.len() > payload_bytes);
        let event = ModernHttpSubscriptionListenEvent::Acknowledged { accepted_filter };
        for (remaining_bytes, fits) in [(payload_bytes, true), (payload_bytes - 1, false)] {
            let mut parser = crate::sse::BoundedSseParser::new(task_sse_limits().unwrap());
            let frames = parser.push(wire.as_bytes()).unwrap();
            assert_eq!(frames.len(), 1);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&frames[0]).unwrap(),
                envelope
            );
            let mut budget = EventBudget {
                notifications: 1,
                remaining_bytes,
            };
            assert_eq!(budget.admit(&event).is_ok(), fits);
            assert_eq!(
                budget.remaining_bytes,
                if fits { 0 } else { remaining_bytes }
            );
            assert_eq!(budget.notifications, usize::from(!fits));
        }
    }

    #[test]
    fn notification_budget_leaves_room_for_an_actual_terminal() {
        let mut budget = EventBudget {
            notifications: 1,
            remaining_bytes: 128,
        };
        budget.charge(&json!({}), true).unwrap();
        assert!(budget.charge(&json!({}), true).is_err());
        budget
            .charge(&json!({"resultType": "complete"}), false)
            .unwrap();
        assert_eq!(budget.notifications, 0);
    }

    #[test]
    fn terminal_is_charged_its_encoded_bytes_and_refused_one_byte_short() {
        let terminal = CompleteResult::new(
            FinalSubscriptionsListenResult {},
            fastmcp_protocol::ResultMeta::empty(),
        );
        let length = encode_complete_result(&terminal.meta, Vec::new(), &[], &terminal.extras)
            .unwrap()
            .len();
        assert!(length >= r#"{"resultType":"complete"}"#.len());

        let mut exact = EventBudget {
            notifications: 0,
            remaining_bytes: length,
        };
        exact.charge_terminal(&terminal).unwrap();
        assert_eq!(exact.remaining_bytes, 0);
        assert_eq!(exact.notifications, 0);

        let mut short = EventBudget {
            notifications: 3,
            remaining_bytes: length - 1,
        };
        assert!(short.charge_terminal(&terminal).is_err());
        assert_eq!(short.remaining_bytes, length - 1);
        assert_eq!(short.notifications, 3);
    }
}
