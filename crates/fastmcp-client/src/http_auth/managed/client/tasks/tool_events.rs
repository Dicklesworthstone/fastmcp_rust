//! Incremental delivery from a Tasks-capable tool call without escaping its login.

use std::io::{self, Write};

use asupersync::Cx;
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};
use fastmcp_protocol::common_types::ExactNonNegativeJsonNumber;
use fastmcp_protocol::{FinalCoreResult, ProgressMarker, ServerNotification};
use serde_json::Value;

use super::{
    ManagedHttpClient, ManagedHttpClientError, TaskCall, TaskResult, checkpoint, task_sse_limits,
};
use crate::http_executor::ModernHttpFinalCoreEvent;
use crate::{
    ClientHttpConnectionError, FinalToolCallOutcome, HttpClient, HttpClientError,
    catch_client_callback_unwind,
};

const MAX_NOTIFICATIONS: usize = 4_096;
const MAX_NOTIFICATION_BYTES: usize = 128 * 1024 * 1024;
const MAX_MARKER_BYTES: usize = 16 * 1024;

type Observer<'a> = &'a mut (dyn FnMut(&ServerNotification) -> McpResult<()> + Send);

pub(in super::super) struct ToolEventRequest<'a> {
    name: &'a str,
    arguments: Value,
    marker: Option<&'a ProgressMarker>,
    budget: EventBudget,
    observer: Observer<'a>,
}

fn refused(message: &'static str) -> HttpClientError {
    HttpClientError::CoreResult(McpError::invalid_request(message))
}

struct ByteBudget(usize);

impl Write for ByteBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("managed tool notification byte limit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct EventBudget {
    remaining: usize,
    bytes: usize,
    last_progress: Option<ExactNonNegativeJsonNumber>,
}

impl EventBudget {
    fn admit(
        &mut self,
        marker: Option<&ProgressMarker>,
        notification: &ServerNotification,
    ) -> Result<(), HttpClientError> {
        if self.remaining == 0 {
            return Err(refused("Managed tool notification limit exceeded"));
        }
        // The low-level listener validates the notification's wire shape. Like
        // the ordinary owned executor, this caller boundary also binds progress
        // to the requested token and enforces strict, exact numeric increase.
        let next_progress = match notification {
            ServerNotification::Progress(progress) => {
                if marker != Some(&progress.progress_token)
                    || self
                        .last_progress
                        .as_ref()
                        .is_some_and(|last| progress.progress.cmp(last).is_le())
                {
                    return Err(refused("Managed tool progress is not request-owned or increasing"));
                }
                Some(progress.progress.clone())
            }
            _ => None,
        };
        let request = notification
            .encode()
            .map_err(|_| refused("Invalid managed tool notification"))?;
        let mut counter = ByteBudget(self.bytes);
        serde_json::to_writer(&mut counter, &request)
            .map_err(|_| refused("Managed tool notification payload limit exceeded"))?;
        // Neither a refused event nor a partly encoded event advances state.
        self.remaining -= 1;
        self.bytes = counter.0;
        if let Some(progress) = next_progress {
            self.last_progress = Some(progress);
        }
        Ok(())
    }
}

impl<'a> ToolEventRequest<'a> {
    fn new(
        name: &'a str,
        arguments: Value,
        marker: Option<&'a ProgressMarker>,
        max_notifications: usize,
        max_notification_bytes: usize,
        observer: Observer<'a>,
    ) -> Result<Self, ManagedHttpClientError> {
        if max_notifications > MAX_NOTIFICATIONS
            || !(1..=MAX_NOTIFICATION_BYTES).contains(&max_notification_bytes)
        {
            return Err(ManagedHttpClientError::InvalidPolicy);
        }
        serde_json::to_writer(&mut ByteBudget(MAX_MARKER_BYTES), &marker)
            .map_err(|_| ManagedHttpClientError::InvalidPolicy)?;
        Ok(Self {
            name,
            arguments,
            marker,
            budget: EventBudget {
                remaining: max_notifications,
                bytes: max_notification_bytes,
                last_progress: None,
            },
            observer,
        })
    }

    pub(super) async fn dispatch(
        mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        client: &mut HttpClient,
        request_id: fastmcp_protocol::RequestId,
    ) -> Result<TaskResult, HttpClientError> {
        // Re-enter both enclosing managed guards before opening the request,
        // even when discovery or the prior operation was immediately ready.
        asupersync::runtime::yield_now().await;
        checkpoint(cx, cancellation)?;
        let mut listener = client
            .connection
            .open_final_tasks_tool_call_listener_with_progress_marker(
                cx,
                request_id,
                self.name,
                self.arguments,
                self.marker,
                task_sse_limits()?,
            )
            .await
            .map_err(HttpClientError::Connection)?;
        loop {
            checkpoint(cx, cancellation)?;
            let event = listener
                .next_event(cx)
                .await
                .map_err(|error| {
                    HttpClientError::Connection(ClientHttpConnectionError::FinalCoreListen(error))
                })?
                .ok_or_else(|| refused("Managed tool stream ended without an outcome"))?;
            asupersync::runtime::yield_now().await;
            checkpoint(cx, cancellation)?;
            let notification = match event {
                ModernHttpFinalCoreEvent::Terminal(terminal) => {
                    let outcome = match terminal {
                        FinalCoreResult::ToolsCall { result, .. } => {
                            FinalToolCallOutcome::Complete(result)
                        }
                        FinalCoreResult::ToolsCallTask { result } => {
                            FinalToolCallOutcome::Task(result)
                        }
                        FinalCoreResult::ToolsCallInputRequired { result, .. } => {
                            FinalToolCallOutcome::InputRequired(result)
                        }
                        _ => return Err(refused("Unexpected managed tool outcome")),
                    };
                    return Ok(TaskResult::Tool(Box::new(outcome)));
                }
                ModernHttpFinalCoreEvent::Progress(progress) => {
                    ServerNotification::Progress(progress)
                }
                ModernHttpFinalCoreEvent::Notification(notification) => notification,
            };
            self.budget.admit(self.marker, &notification)?;
            // Encoding a large admitted notification can consume the remaining
            // lifetime too. Do not start host effects until both guards check it.
            asupersync::runtime::yield_now().await;
            checkpoint(cx, cancellation)?;
            let observed = catch_client_callback_unwind(|| (self.observer)(&notification));
            // A ready callback can close/revoke its login or cancel this request.
            // Check those signals before reading even an already-buffered final.
            asupersync::runtime::yield_now().await;
            checkpoint(cx, cancellation)?;
            match observed {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    return Err(HttpClientError::CoreResult(McpError::new(
                        error.code,
                        "Managed tool observer refused further delivery",
                    )));
                }
                Err(_) => {
                    return Err(HttpClientError::CoreResult(McpError::internal_error(
                        "Managed tool observer failed",
                    )));
                }
            }
        }
    }
}

impl ManagedHttpClient {
    /// Calls a Tasks-capable tool and delivers its notifications before completion.
    ///
    /// Requires `with_tasks` and bilateral Tasks admission. Progress is delivered
    /// only for the supplied exact marker and must strictly increase; log and
    /// other native-admitted core notifications retain wire order. The callback
    /// never receives the terminal: the exact Complete, Task or InputRequired
    /// outcome is returned instead. No reverse input is automatically answered.
    ///
    /// All I/O and callbacks share one original credential and one deadline.
    /// No live stream escapes. A callback error or panic stops local delivery;
    /// it does not undo a tool invocation, cancel a remote Task, or retry anything.
    /// Use caller cancellation to stop a quiet response. Callbacks must not block.
    ///
    /// `max_notifications` is 0..=4096; zero permits a notification-free result.
    /// `max_notification_bytes` is 1..=128 MiB of encoded JSON-RPC notifications,
    /// not a heap or raw-SSE limit. Progress marker JSON is at most 16 KiB. Native
    /// response frames and the terminal retain their separate 8 MiB bound and
    /// 4096-data-line limit. No notification history is retained by this method.
    ///
    /// An admitted call retires its connection even on success: received catalog
    /// changes must not leave the ordinary client's caches or cursors reusable.
    /// Invalid local limits leave an existing connection untouched. Independent
    /// clients and application-owned caches still require their own invalidation.
    #[allow(clippy::too_many_arguments)]
    pub async fn call_tool_final_outcome_with_events(
        &mut self,
        cx: &Cx,
        name: &str,
        arguments: Value,
        progress_marker: Option<&ProgressMarker>,
        max_notifications: usize,
        max_notification_bytes: usize,
        observer: &mut (dyn FnMut(&ServerNotification) -> McpResult<()> + Send),
    ) -> Result<FinalToolCallOutcome, ManagedHttpClientError> {
        self.call_tool_final_outcome_with_events_and_cancellation(
            cx,
            &McpRequestCancellation::new(),
            name,
            arguments,
            progress_marker,
            max_notifications,
            max_notification_bytes,
            observer,
        )
        .await
    }

    /// Live tool notifications with an operation-local cancellation domain.
    #[allow(clippy::too_many_arguments)]
    pub async fn call_tool_final_outcome_with_events_and_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        name: &str,
        arguments: Value,
        progress_marker: Option<&ProgressMarker>,
        max_notifications: usize,
        max_notification_bytes: usize,
        observer: &mut (dyn FnMut(&ServerNotification) -> McpResult<()> + Send),
    ) -> Result<FinalToolCallOutcome, ManagedHttpClientError> {
        self.admit_tasks(cx, cancellation)?;
        let request = ToolEventRequest::new(
            name,
            arguments,
            progress_marker,
            max_notifications,
            max_notification_bytes,
            observer,
        )?;
        let result = self
            .perform_task(cx, cancellation, TaskCall::ToolEvents(request))
            .await;
        // Failure/abandonment already retires custody in perform_any. Successful
        // delivery also discards stale discovery and all pending cursor handles.
        self.connection = None;
        match result? {
            TaskResult::Tool(result) => Ok(*result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{FinalProgressNotificationParams, JsonRpcRequest};
    use serde_json::json;

    fn progress(token: Value, value: &str) -> ServerNotification {
        let params: FinalProgressNotificationParams = serde_json::from_str(&format!(
            "{{\"progressToken\":{token},\"progress\":{value}}}"
        ))
        .unwrap();
        ServerNotification::Progress(params)
    }

    fn budget() -> EventBudget {
        EventBudget {
            remaining: 4,
            bytes: 8192,
            last_progress: None,
        }
    }

    #[test]
    fn progress_is_bound_to_exact_token_type_and_strict_exact_numeric_order() {
        let marker: ProgressMarker = serde_json::from_value(json!("7")).unwrap();
        let mut budget = budget();
        for token in [json!(7), json!("other")] {
            assert!(budget.admit(Some(&marker), &progress(token, "1")).is_err());
        }
        assert_eq!(budget.remaining, 4);
        // These adjacent integers collapse to one value through f64.
        budget
            .admit(Some(&marker), &progress(json!("7"), "9007199254740992"))
            .unwrap();
        budget
            .admit(Some(&marker), &progress(json!("7"), "9007199254740993"))
            .unwrap();
        for value in ["9007199254740993", "9007199254740992"] {
            assert!(budget.admit(Some(&marker), &progress(json!("7"), value)).is_err());
        }
        assert_eq!(budget.remaining, 2);
        assert!(budget.admit(None, &progress(json!("7"), "9007199254740994")).is_err());
    }

    #[test]
    fn notification_bytes_are_cumulative_and_failed_admission_is_atomic() {
        let notification = ServerNotification::decode(&JsonRpcRequest::notification(
            "notifications/tools/list_changed",
            Some(json!({})),
        ))
        .unwrap();
        let bytes = serde_json::to_vec(&notification.encode().unwrap()).unwrap().len();
        let mut budget = EventBudget {
            remaining: 3,
            bytes: 2 * bytes,
            last_progress: None,
        };
        budget.admit(None, &notification).unwrap();
        budget.admit(None, &notification).unwrap();
        assert_eq!((budget.remaining, budget.bytes), (1, 0));
        assert!(budget.admit(None, &notification).is_err());
        assert_eq!((budget.remaining, budget.bytes), (1, 0));
    }

    #[test]
    fn byte_refusal_does_not_advance_the_progress_watermark() {
        let marker: ProgressMarker = serde_json::from_value(json!(0)).unwrap();
        let notification = progress(json!(0), "1.0000000000000000000001");
        let bytes = serde_json::to_vec(&notification.encode().unwrap()).unwrap().len();
        let mut budget = EventBudget {
            remaining: 1,
            bytes: bytes - 1,
            last_progress: None,
        };
        assert!(budget.admit(Some(&marker), &notification).is_err());
        assert!(budget.last_progress.is_none());
        assert_eq!((budget.remaining, budget.bytes), (1, bytes - 1));
        budget.bytes = bytes;
        budget.admit(Some(&marker), &notification).unwrap();
        assert_eq!((budget.remaining, budget.bytes), (0, 0));
    }

    #[test]
    fn limits_allow_zero_notifications_but_refuse_unbounded_configuration() {
        let mut observer = |_: &ServerNotification| Ok(());
        assert!(ToolEventRequest::new("tool", json!({}), None, 0, 1, &mut observer).is_ok());
        for (count, bytes) in [
            (MAX_NOTIFICATIONS + 1, 1),
            (1, 0),
            (1, MAX_NOTIFICATION_BYTES + 1),
        ] {
            assert!(matches!(
                ToolEventRequest::new("tool", json!({}), None, count, bytes, &mut observer),
                Err(ManagedHttpClientError::InvalidPolicy)
            ));
        }
        let marker: ProgressMarker =
            serde_json::from_value(json!("x".repeat(MAX_MARKER_BYTES))).unwrap();
        assert!(
            ToolEventRequest::new("tool", json!({}), Some(&marker), 1, 4096, &mut observer).is_err()
        );
        let mut zero = budget();
        zero.remaining = 0;
        assert!(zero.admit(None, &progress(json!(1), "1")).is_err());
        assert_eq!((zero.remaining, zero.bytes), (0, 8192));
    }
}
