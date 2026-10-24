//! Core catalog and resource notifications inside one managed OAuth operation.
//!
//! The native listener owns acknowledgement, filter, correlation and terminal
//! validation. This layer owns finite application budgets and callback admission.

use std::io::{self, Write};
use std::ops::ControlFlow;

use asupersync::Cx;
use fastmcp_core::{McpError, McpRequestCancellation};
use fastmcp_protocol::{
    CompleteResult, FinalSubscriptionsListenResult, SubscriptionFilter, encode_complete_result,
};
use serde::Serialize;

use super::callbacks::CallbackBoundary;
use super::{Call, CallResult, ManagedHttpClient, ManagedHttpClientError};
use crate::http_executor::ModernHttpSubscriptionListenEvent;
use crate::sse::SseLimits;
use crate::{ClientHttpConnectionError, HttpClient, HttpClientError, catch_client_callback_unwind};

const MAX_FILTER_BYTES: usize = 64 * 1024;
const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_NOTIFICATIONS: usize = 4_096;
const MAX_PAYLOAD_BYTES: usize = 128 * 1024 * 1024;

pub(super) type ListenResult = Option<Box<CompleteResult<FinalSubscriptionsListenResult>>>;
type Observer<'a> =
    &'a mut (dyn FnMut(&ModernHttpSubscriptionListenEvent) -> ControlFlow<()> + Send);

pub(super) struct ListenRequest<'a> {
    filter: SubscriptionFilter,
    budget: EventBudget,
    observer: Observer<'a>,
}

fn refusal(message: &'static str) -> HttpClientError {
    HttpClientError::CoreResult(McpError::invalid_request(message))
}

struct ByteBudget(usize);

impl Write for ByteBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("managed core subscription byte limit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct EventBudget {
    notifications: usize,
    bytes: usize,
}

impl EventBudget {
    fn charge(&mut self, value: &impl Serialize) -> Result<(), HttpClientError> {
        if self.notifications == 0 {
            return Err(refusal("Managed core subscription notification limit exceeded"));
        }
        let mut remaining = ByteBudget(self.bytes);
        serde_json::to_writer(&mut remaining, value)
            .map_err(|_| refusal("Managed core subscription payload limit exceeded"))?;
        // Failed admission never spends part of the allowance or calls the host.
        self.bytes = remaining.0;
        self.notifications -= 1;
        Ok(())
    }

    fn admit(&mut self, event: &ModernHttpSubscriptionListenEvent) -> Result<(), HttpClientError> {
        match event {
            ModernHttpSubscriptionListenEvent::Acknowledged { accepted_filter } => {
                // Core selection cannot gain an extension through an ACK, even
                // when this client has used a Tasks-enabled connection before.
                if !accepted_filter.additional.is_empty() {
                    return Err(refusal("Extension filter on a managed core subscription"));
                }
                self.charge(accepted_filter)
            }
            ModernHttpSubscriptionListenEvent::Notification(notification) => {
                // ServerNotification deliberately has no Serialize impl. Use its
                // existing wire encoder, not an ad hoc enum or Debug encoding.
                let request = notification
                    .encode()
                    .map_err(|_| refusal("Invalid managed core subscription notification"))?;
                self.charge(&request)
            }
            ModernHttpSubscriptionListenEvent::Terminal { result, .. } => {
                // CompleteResult also owns a protocol encoder rather than serde.
                // A terminal consumes bytes but not the notification allowance.
                let encoded = encode_complete_result(&result.meta, Vec::new(), &[], &result.extras)
                    .map_err(|_| refusal("Invalid managed core subscription terminal"))?;
                self.bytes = self
                    .bytes
                    .checked_sub(encoded.len())
                    .ok_or_else(|| refusal("Managed core subscription payload limit exceeded"))?;
                Ok(())
            }
            #[cfg(feature = "tasks")]
            ModernHttpSubscriptionListenEvent::TaskNotification(_) => {
                Err(refusal("Task notification on a managed core subscription"))
            }
        }
    }
}

impl<'a> ListenRequest<'a> {
    fn new(
        filter: SubscriptionFilter,
        max_notifications: usize,
        max_payload_bytes: usize,
        observer: Observer<'a>,
    ) -> Result<Self, ManagedHttpClientError> {
        if !(1..=MAX_NOTIFICATIONS).contains(&max_notifications)
            || !(1..=MAX_PAYLOAD_BYTES).contains(&max_payload_bytes)
            || !filter.additional.is_empty()
        {
            return Err(ManagedHttpClientError::InvalidPolicy);
        }
        // Bound caller-provided URI selections before token acquisition or I/O.
        // Native construction still validates the complete request envelope.
        serde_json::to_writer(&mut ByteBudget(MAX_FILTER_BYTES), &filter)
            .map_err(|_| ManagedHttpClientError::InvalidPolicy)?;
        Ok(Self {
            filter,
            budget: EventBudget {
                notifications: max_notifications,
                bytes: max_payload_bytes,
            },
            observer,
        })
    }

    pub(super) async fn dispatch(
        mut self,
        cx: &Cx,
        client: &mut HttpClient,
        boundary: &CallbackBoundary,
    ) -> Result<ListenResult, HttpClientError> {
        boundary.check(cx).map_err(HttpClientError::CoreResult)?;
        // Wire framing is independent of the aggregate application budget:
        // JSON-RPC/SSE overhead cannot reject an exactly fitting payload.
        let limits = SseLimits::with_data_lines(
            MAX_FRAME_BYTES + 8,
            MAX_FRAME_BYTES,
            64,
            4_096,
        )
        .ok_or_else(|| refusal("Invalid managed core subscription framing limits"))?;
        let id = client.next_request_id()?;
        let mut listener = client
            .connection
            .open_subscriptions_listener(cx, id, self.filter, limits)
            .await
            .map_err(HttpClientError::Connection)?;
        loop {
            boundary.check(cx).map_err(HttpClientError::CoreResult)?;
            let event = listener
                .next_event(cx)
                .await
                .map_err(|error| {
                    HttpClientError::Connection(ClientHttpConnectionError::SubscriptionsListen(
                        error,
                    ))
                })?
                .ok_or_else(|| refusal("Managed core subscription ended without a terminal"))?;
            self.budget.admit(&event)?;
            boundary.check(cx).map_err(HttpClientError::CoreResult)?;
            if let ModernHttpSubscriptionListenEvent::Terminal { result, .. } = event {
                return Ok(Some(Box::new(result)));
            }
            let observed = catch_client_callback_unwind(|| (self.observer)(&event));
            // Check even a panic or Break: a callback can close its login or
            // revoke its token synchronously before returning in this same poll.
            boundary.check(cx).map_err(HttpClientError::CoreResult)?;
            let decision = observed.map_err(|_| {
                HttpClientError::CoreResult(McpError::internal_error(
                    "Managed core subscription observer failed",
                ))
            })?;
            if decision.is_break() {
                listener.cancel();
                return Ok(None);
            }
            // Coalesced frames must not monopolize a cooperative executor.
            // The enclosing managed guards retain all timers and wakeups.
            asupersync::runtime::yield_now().await;
        }
    }
}

impl ManagedHttpClient {
    /// Delivers core catalog changes and resource updates over one HTTP listen.
    ///
    /// Uses the same authenticated discovery, explicit resource TLS trust and
    /// original credential lifetime as ordinary managed calls. The native
    /// listener checks the first ACK, accepted-filter subset, notification
    /// category/resource URI and subscription correlation before host delivery.
    /// No Tasks feature or `with_tasks` selection is required. Extension filter
    /// members, including an empty `taskIds` selection, refuse before any I/O.
    ///
    /// The observer receives the ACK and subsequent notifications, not the
    /// terminal result. `Break(())` stops locally and returns `Ok(None)`;
    /// `Ok(Some(result))` is the peer's correlated terminal. EOF without that
    /// terminal is an error. This preserves native terminal admission and does
    /// not add a separate trailing-body/EOF verification after the terminal.
    ///
    /// The one managed deadline includes acquisition, discovery, idle time and
    /// callbacks. Logout, cancellation, revocation and expiry stop subsequent
    /// callbacks, including buffered records. No response stream escapes, and
    /// no reconnect, replay, token refresh or cancellation POST occurs inside
    /// the listen. Callbacks must not block; already-performed host effects
    /// cannot be rolled back by a later error or deadline.
    ///
    /// Once started, every completed, stopped, failed or abandoned listen
    /// retires this client's connection, discovery/cache state and catalog cursors.
    /// A later explicit call discovers afresh. An ACK does not recover missed
    /// history: reconcile snapshots after a gap, and invalidate any separate
    /// application caches or sibling clients explicitly. Rejection before
    /// operation admission preserves existing connection and cursor state.
    ///
    /// `max_notifications` is 1..=4096, including the ACK, excluding the terminal.
    /// `max_payload_bytes` is 1..=128 MiB, counting serialized accepted filters,
    /// encoded JSON-RPC notifications and encoded complete terminal results.
    /// It is not a wire or heap-size bound. Independent native framing limits
    /// are 8 MiB and 4096 data lines per SSE event; filter JSON is at most 64 KiB.
    pub async fn listen_core_events(
        &mut self,
        cx: &Cx,
        filter: SubscriptionFilter,
        max_notifications: usize,
        max_payload_bytes: usize,
        observer: &mut (dyn FnMut(&ModernHttpSubscriptionListenEvent) -> ControlFlow<()> + Send),
    ) -> Result<Option<CompleteResult<FinalSubscriptionsListenResult>>, ManagedHttpClientError> {
        self.listen_core_events_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            filter,
            max_notifications,
            max_payload_bytes,
            observer,
        )
        .await
    }

    /// Core event delivery with cancellation isolated from the shared login.
    #[allow(clippy::too_many_arguments)]
    pub async fn listen_core_events_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        filter: SubscriptionFilter,
        max_notifications: usize,
        max_payload_bytes: usize,
        observer: &mut (dyn FnMut(&ModernHttpSubscriptionListenEvent) -> ControlFlow<()> + Send),
    ) -> Result<Option<CompleteResult<FinalSubscriptionsListenResult>>, ManagedHttpClientError> {
        if self.closed {
            return Err(ManagedHttpClientError::Closed);
        }
        self.session.check(cx, cancellation)?;
        let request = ListenRequest::new(filter, max_notifications, max_payload_bytes, observer)?;
        match self
            .perform_any(cx, cancellation, Call::CoreListen(request))
            .await?
        {
            CallResult::CoreListen(result) => Ok(result.map(|result| *result)),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{JsonRpcRequest, RequestId, ResultMeta, ServerNotification};
    use serde_json::json;

    #[test]
    fn filters_and_bounds_are_admitted_before_an_operation_can_start() {
        let mut observer = |_: &ModernHttpSubscriptionListenEvent| ControlFlow::Continue(());
        for (count, bytes) in [(1, 1), (MAX_NOTIFICATIONS, MAX_PAYLOAD_BYTES)] {
            assert!(
                ListenRequest::new(SubscriptionFilter::default(), count, bytes, &mut observer)
                    .is_ok()
            );
        }
        for (count, bytes) in [
            (0, 1),
            (1, 0),
            (MAX_NOTIFICATIONS + 1, 1),
            (1, MAX_PAYLOAD_BYTES + 1),
            (usize::MAX, usize::MAX),
        ] {
            assert!(matches!(
                ListenRequest::new(SubscriptionFilter::default(), count, bytes, &mut observer),
                Err(ManagedHttpClientError::InvalidPolicy)
            ));
        }
        for key in ["taskIds", "unknown-extension"] {
            let mut filter = SubscriptionFilter::default();
            filter.additional.insert(key.to_owned(), json!([]));
            assert!(ListenRequest::new(filter, 1, 4096, &mut observer).is_err());
        }
    }

    #[test]
    fn filter_limit_counts_encoded_bytes_instead_of_uri_count() {
        let mut observer = |_: &ModernHttpSubscriptionListenEvent| ControlFlow::Continue(());
        let filter = SubscriptionFilter {
            resource_subscriptions: Some(vec![format!(
                "file:///{}",
                "x".repeat(MAX_FILTER_BYTES)
            )]),
            ..SubscriptionFilter::default()
        };
        assert!(ListenRequest::new(filter, 1, 4096, &mut observer).is_err());
    }

    #[test]
    fn failed_charge_preserves_both_allowances() {
        let value = json!({"quoted": "\"\\\n雪"});
        let bytes = serde_json::to_vec(&value).unwrap().len();
        let mut budget = EventBudget {
            notifications: 2,
            bytes: bytes - 1,
        };
        assert!(budget.charge(&value).is_err());
        assert_eq!(budget.notifications, 2);
        assert_eq!(budget.bytes, bytes - 1);
        budget.bytes = bytes;
        budget.charge(&value).unwrap();
        assert_eq!(budget.notifications, 1);
        assert_eq!(budget.bytes, 0);
    }

    #[test]
    fn core_ack_cannot_gain_an_extension_or_spend_budget_on_refusal() {
        let mut filter = SubscriptionFilter::default();
        filter.additional.insert("taskIds".to_owned(), json!([]));
        let mut budget = EventBudget {
            notifications: 1,
            bytes: 4096,
        };
        assert!(
            budget
                .admit(&ModernHttpSubscriptionListenEvent::Acknowledged {
                    accepted_filter: filter,
                })
                .is_err()
        );
        assert_eq!(budget.notifications, 1);
        assert_eq!(budget.bytes, 4096);
        budget
            .admit(&ModernHttpSubscriptionListenEvent::Acknowledged {
                accepted_filter: SubscriptionFilter::default(),
            })
            .unwrap();
        assert_eq!(budget.notifications, 0);
    }

    #[test]
    fn notification_accounting_uses_the_existing_wire_encoder() {
        let request = JsonRpcRequest::notification(
            "notifications/tools/list_changed",
            Some(json!({"_meta": {"io.modelcontextprotocol/subscriptionId": 41}})),
        );
        let notification = ServerNotification::decode(&request).unwrap();
        let bytes = serde_json::to_vec(&notification.encode().unwrap())
            .unwrap()
            .len();
        let event = ModernHttpSubscriptionListenEvent::Notification(notification);
        for allowance in [bytes - 1, bytes] {
            let mut budget = EventBudget {
                notifications: 1,
                bytes: allowance,
            };
            assert_eq!(budget.admit(&event).is_ok(), allowance == bytes);
            assert_eq!(budget.notifications, usize::from(allowance != bytes));
        }
    }

    #[test]
    fn terminal_can_use_remaining_bytes_after_notification_allowance_is_exhausted() {
        let result = CompleteResult::new(FinalSubscriptionsListenResult {}, ResultMeta::empty());
        let bytes = encode_complete_result(&result.meta, Vec::new(), &[], &result.extras)
            .unwrap()
            .len();
        let event = ModernHttpSubscriptionListenEvent::Terminal {
            subscription_id: RequestId::Number(41),
            result,
        };
        for allowance in [bytes - 1, bytes] {
            let mut budget = EventBudget {
                notifications: 0,
                bytes: allowance,
            };
            assert_eq!(budget.admit(&event).is_ok(), allowance == bytes);
            assert_eq!(budget.notifications, 0);
            assert_eq!(budget.bytes, if allowance == bytes { 0 } else { allowance });
        }
    }
}
