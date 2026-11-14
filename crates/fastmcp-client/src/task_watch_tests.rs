//! Live transport coverage for caller-owned Task subscription watches.

use super::*;
use asupersync::runtime::RuntimeBuilder;
use fastmcp_protocol::{
    DiscoveryCacheHints, ServerBehavior, ServerBehaviorRegistry, ServerDiscoverCapabilities,
    ServerDiscoverResult, ServerInfo,
};
use serde_json::json;

const CREATED: &str = "2026-07-28T00:00:00Z";
const EXACT_RESULT: &str =
    r#"{"x-first":1.20e+4,"content":[],"x-zero":-0,"x-last":123456789012345678901234567890}"#;

fn discovery() -> String {
    let capabilities = ServerDiscoverCapabilities::from_registry(
        &ServerBehaviorRegistry::from_behaviors([
            ServerBehavior::ToolsList,
            ServerBehavior::ToolsListChangedNotification,
            ServerBehavior::SubscriptionsListen,
        ]),
        std::collections::BTreeMap::from([(
            fastmcp_protocol::TASKS_EXTENSION.to_owned(),
            json!({}),
        )]),
    )
    .unwrap();
    let result = ServerDiscoverResult::new(
        capabilities,
        ServerInfo {
            name: "task-stream-peer".to_owned(),
            version: "1".to_owned(),
        },
        None,
        DiscoveryCacheHints::private_ttl_ms(0),
    );
    let mut response = json!({"jsonrpc":"2.0", "id":1, "result":result});
    response["result"]["supportedVersions"] = json!([crate::MODERN_PROTOCOL_VERSION]);
    response.to_string()
}

fn live_ttl(seconds: u64) -> u64 {
    let created = fastmcp_protocol::TaskTimestamp::parse(CREATED).unwrap();
    let remaining = wall_now_nanos() - timestamp_nanos(&created).unwrap();
    u64::try_from(remaining / 1_000_000).unwrap() + seconds * 1_000
}

fn task(status: &str, ttl: Option<u64>, updated_second: u8) -> String {
    let ttl = ttl.map_or_else(|| "null".to_owned(), |value| value.to_string());
    let result = if status == "completed" {
        format!(r#", "result":{EXACT_RESULT}"#)
    } else {
        String::new()
    };
    format!(
        r#"{{"taskId":"stream-task","status":"{status}","createdAt":"{CREATED}","lastUpdatedAt":"2026-07-28T00:00:{updated_second:02}Z","ttlMs":{ttl}{result}}}"#
    )
}

fn response(id: i64, task: &str) -> String {
    let result = format!(r#"{{"resultType":"complete",{}"#, &task[1..]);
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#)
}

fn notification(id: i64, task: &str) -> String {
    let params = format!(
        r#"{{"_meta":{{"io.modelcontextprotocol/subscriptionId":{id}}},"diagnostic":{{"opaque":true}},{}"#,
        &task[1..]
    );
    format!(r#"{{"jsonrpc":"2.0","method":"notifications/tasks","params":{params}}}"#)
}

fn ack(id: i64, tasks: serde_json::Value) -> String {
    json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged", "params":{
        "_meta":{"io.modelcontextprotocol/subscriptionId":id}, "notifications":{"taskIds":tasks}
    }})
    .to_string()
}

fn completion(id: i64) -> String {
    json!({"jsonrpc":"2.0", "id":id, "result":{
        "resultType":"complete", "_meta":{"io.modelcontextprotocol/subscriptionId":id}
    }})
    .to_string()
}

fn assert_completed(task: &FinalTask) {
    let FinalTask::Completed { result, .. } = task else {
        panic!("terminal completion expected")
    };
    assert_eq!(serde_json::to_string(result).unwrap(), EXACT_RESULT);
}

fn drive_policy() -> FinalTaskDrivePolicy {
    FinalTaskDrivePolicy::new(
        FinalTaskWaitPolicy::new(Duration::from_secs(3), 8, Duration::from_millis(40)).unwrap(),
        4,
        8,
        64 * 1024,
        64 * 1024,
    )
    .unwrap()
}

fn with_poll(snapshot: &str, millis: u64) -> String {
    format!(r#"{{"pollIntervalMs":{millis},{}"#, &snapshot[1..])
}

fn input_task(updated_second: u8, later: bool) -> String {
    let mut inputs = json!({"roots":{"method":"roots/list"}});
    if later {
        inputs["later"] = json!({"method":"roots/list"});
    }
    format!(
        r#"{{"inputRequests":{inputs},{}"#,
        &task("input_required", None, updated_second)[1..]
    )
}

// A scripted unit proof for the shared opening handoff. The transport tests
// below separately exercise real stdio and WebSocket ownership and ingress.
mod opening_handoff {
    use super::*;
    use std::cell::Cell;

    #[derive(Default)]
    struct CancellingOpen {
        opens: usize,
        reads: usize,
        updates: usize,
        events: usize,
        input_contexts: Cell<usize>,
        retired: Vec<RequestId>,
    }

    impl TaskInputTransport for CancellingOpen {
        type Error = McpError;

        async fn read(
            &mut self,
            _: &Cx,
            _: &McpRequestCancellation,
            _: FinalTaskId,
        ) -> McpResult<FinalTask> {
            self.reads += 1;
            Err(McpError::internal_error(
                "unexpected read after cancelled open",
            ))
        }

        fn input_context(&self) -> McpResult<(crate::ReverseRequestHandlers, serde_json::Value)> {
            self.input_contexts.set(self.input_contexts.get() + 1);
            Err(McpError::internal_error(
                "unexpected input after cancelled open",
            ))
        }

        async fn update(
            &mut self,
            _: &Cx,
            _: &McpRequestCancellation,
            _: &FinalTask,
            _: FinalTaskInputResponses,
        ) -> McpResult<FinalUpdateTaskResult> {
            self.updates += 1;
            Err(McpError::internal_error(
                "unexpected update after cancelled open",
            ))
        }
    }

    impl TaskDriveWatchTransport for CancellingOpen {
        type Listener = RequestId;
        type Options = ();

        async fn open_drive_watch(
            &mut self,
            _: &Cx,
            cancellation: &McpRequestCancellation,
            _: SubscriptionFilter,
            (): (),
            listener: &mut Option<Self::Listener>,
        ) -> McpResult<()> {
            self.opens += 1;
            *listener = Some(RequestId::Number(41));
            // Commit the listener, then elect cancellation in the same poll.
            // WaitBudget must suppress success without losing this ownership.
            cancellation.cancel();
            Ok(())
        }

        async fn next_drive_event(
            &mut self,
            _: &Cx,
            _: &McpRequestCancellation,
            _: &mut Self::Listener,
        ) -> McpResult<StdioTaskSubscriptionEvent> {
            self.events += 1;
            Err(McpError::internal_error(
                "unexpected event after cancelled open",
            ))
        }

        fn abandon_drive_watch(&mut self, listener: Self::Listener) {
            self.retired.push(listener);
        }
    }

    #[test]
    fn task_watch_driver_retires_owner_when_open_finishes_cancelled() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let initial: FinalTask = serde_json::from_str(&input_task(1, false)).unwrap();
                let before = serde_json::to_vec(&initial).unwrap();
                let mut driver = FinalTaskHandle::new(initial).into_driver(drive_policy());
                let mut transport = CancellingOpen::default();
                let cancellation = McpRequestCancellation::new();
                for _ in 0..2 {
                    assert_eq!(
                        drive_task_watching(&mut driver, &cx, &mut transport, &cancellation, (),)
                            .await
                            .unwrap(),
                        FinalTaskWaitOutcome::ObservationCancelled
                    );
                }
                assert_eq!(transport.opens, 1, "a cancelled retry makes no new contact");
                assert_eq!(transport.retired, vec![RequestId::Number(41)]);
                assert_eq!(
                    (transport.reads, transport.updates, transport.events),
                    (0, 0, 0)
                );
                assert_eq!(
                    transport.input_contexts.get(),
                    0,
                    "no Host callback can be selected"
                );
                assert_eq!(serde_json::to_vec(driver.task()).unwrap(), before);
                assert!(!driver.input_resolution_interrupted());
            });
    }
}

#[cfg(unix)]
mod stdio {
    use super::*;
    use crate::{
        ClientBuilder, ClientProtocolPlan, ProtocolPolicy, RequestTimeoutPolicy,
        StdioSubscriptionEvent,
    };

    const START: &str = r#"
IFS= read -r discover || exit 81
case "$discover" in *'"method":"server/discover"'*) ;; *) exit 82 ;; esac
printf '%s\n' "$1"
IFS= read -r attach || exit 83
case "$attach" in *'"id":2'*) ;; *) exit 84 ;; esac
"#;

    async fn connect(cx: &Cx, script: &str) -> (Client, FinalTaskHandle) {
        connect_with_handlers(cx, script, crate::ReverseRequestHandlers::new()).await
    }

    async fn connect_with_handlers(
        cx: &Cx,
        script: &str,
        handlers: crate::ReverseRequestHandlers,
    ) -> (Client, FinalTaskHandle) {
        let mut client = ClientBuilder::new()
            .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
            .reverse_request_handlers(handlers)
            .request_timeout_policy(
                RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(2)).unwrap(),
            )
            .connect_stdio_with_cx(cx, "sh", &["-c", script, "task-stream-peer", &discovery()])
            .await
            .unwrap();
        let handle = client
            .attach_final_task_with_cx(
                cx,
                &McpRequestCancellation::new(),
                FinalTaskId::parse("stream-task").unwrap(),
            )
            .await
            .unwrap();
        (client, handle)
    }

    fn finish_script(next_id: i64) -> String {
        format!(
            r#"
IFS= read -r sibling || exit 97
case "$sibling" in *'"method":"tasks/get"'*) ;; *) exit 98 ;; esac
case "$sibling" in *'"id":{next_id}'*) ;; *) exit 99 ;; esac
printf '%s\n' '{}'
exec sleep 10
"#,
            response(next_id, &task("cancelled", None, 9))
        )
    }

    async fn finish(cx: &Cx, client: &mut Client) {
        let result = client
            .get_task_final_with_cx(
                cx,
                &McpRequestCancellation::new(),
                FinalTaskId::parse("stream-task").unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(result.task, FinalTask::Cancelled(_)));
        client.close_with_cx(cx).await.unwrap();
    }

    #[test]
    fn public_stdio_task_watch_driver_resolves_inputs_and_delivers_early_completion() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&calls);
                let handlers =
                    crate::ReverseRequestHandlers::new().with_modern_roots_list(move |_, _, _| {
                        observed.fetch_add(1, Ordering::SeqCst);
                        Box::pin(async {
                            Ok(crate::FinalEmbeddedRootsListResult { roots: vec![] })
                        })
                    });
                let script = format!(
                    r#"{START}
printf '%s\n' '{}'
IFS= read -r listen || exit 85
case "$listen" in *'"method":"subscriptions/listen"'*) ;; *) exit 86 ;; esac
printf '%s\n' '{}'
IFS= read -r first || exit 87
case "$first" in *'"method":"tasks/get"'*) ;; *) exit 88 ;; esac
printf '%s\n' '{}' '{}'
IFS= read -r update || exit 89
case "$update" in *'"inputResponses":{{"roots":{{"roots":[]}}}}'*) ;; *) exit 90 ;; esac
printf '%s\n' '{{"jsonrpc":"2.0","id":5,"result":{{"resultType":"complete"}}}}' '{}' '{}'
IFS= read -r reconcile || exit 91
case "$reconcile" in *'"method":"tasks/get"'*) ;; *) exit 92 ;; esac
printf '%s\n' '{}'
IFS= read -r update || exit 93
case "$update" in *'"inputResponses":{{"later":{{"roots":[]}}}}'*) ;; *) exit 94 ;; esac
printf '%s\n' '{{"jsonrpc":"2.0","id":7,"result":{{"resultType":"complete"}}}}'
IFS= read -r reconcile || exit 95
case "$reconcile" in *'"method":"tasks/get"'*) ;; *) exit 96 ;; esac
printf '%s\n' '{}' '{}'
IFS= read -r cancel || exit 97
case "$cancel" in *'"requestId":3'*) ;; *) exit 98 ;; esac
{}
"#,
                    response(2, &task("working", None, 1)),
                    ack(3, json!(["stream-task"])),
                    response(4, &with_poll(&task("working", None, 1), 600_001)),
                    notification(3, &input_task(2, false)),
                    notification(3, &input_task(2, false)),
                    notification(3, &input_task(3, true)),
                    response(6, &input_task(3, true)),
                    response(8, &with_poll(&task("working", None, 4), 600_001)),
                    notification(3, &task("completed", None, 5)),
                    finish_script(9)
                );
                let (mut client, handle) = connect_with_handlers(&cx, &script, handlers).await;
                let mut driver = handle.into_driver(drive_policy());
                let live = McpRequestCancellation::new();
                assert_eq!(
                    driver
                        .drive_watching_with_stdio(&cx, &mut client, &live)
                        .await
                        .unwrap(),
                    FinalTaskWaitOutcome::Completed
                );
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    2,
                    "an answered key is never replayed"
                );
                assert!(!driver.input_resolution_interrupted());
                assert_completed(driver.task());
                assert_eq!(
                    driver
                        .drive_watching_with_stdio(&cx, &mut client, &live)
                        .await
                        .unwrap(),
                    FinalTaskWaitOutcome::Completed,
                    "a terminal Task opens no second listener"
                );
                finish(&cx, &mut client).await;
            });
    }

    #[test]
    fn public_stdio_task_watch_driver_preserves_partial_ingress_across_due_poll() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let terminal = notification(3, &task("completed", None, 2));
                let (prefix, suffix) = terminal.split_at(65);
                let script = format!(
                    r#"{START}
printf '%s\n' '{}'
IFS= read -r listen || exit 85
printf '%s\n' '{}'
IFS= read -r reconcile || exit 86
case "$reconcile" in *'"method":"tasks/get"'*) ;; *) exit 87 ;; esac
case "$reconcile" in *'"id":4'*) ;; *) exit 88 ;; esac
printf '%s\n' '{}'
printf '%s' '{prefix}'
IFS= read -r poll || exit 89
case "$poll" in *'"method":"tasks/get"'*) ;; *) exit 90 ;; esac
case "$poll" in *'"id":5'*) ;; *) exit 91 ;; esac
printf '%s\n' '{suffix}' '{}'
IFS= read -r cancel || exit 92
case "$cancel" in *'"requestId":3'*) ;; *) exit 93 ;; esac
{}
"#,
                    response(2, &task("working", None, 1)),
                    ack(3, json!(["stream-task"])),
                    response(4, &with_poll(&task("working", None, 1), 40)),
                    response(5, &with_poll(&task("working", None, 1), 600_001)),
                    finish_script(6)
                );
                let (mut client, handle) = connect(&cx, &script).await;
                let mut driver = handle.into_driver(drive_policy());
                assert_eq!(driver.drive_watching_with_stdio(
                &cx, &mut client, &McpRequestCancellation::new(),
            ).await.unwrap(), FinalTaskWaitOutcome::Completed);
                assert_completed(driver.task());
                finish(&cx, &mut client).await;
            });
    }

    #[test]
    fn public_stdio_task_watch_driver_cancellation_preserves_uncertain_input_custody() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };

        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let owned = Arc::new(Mutex::new(None));
                let observing = McpRequestCancellation::new();
                let cancelled = observing.clone();
                let observed = Arc::clone(&calls);
                let callback_owner = Arc::clone(&owned);
                let handlers = crate::ReverseRequestHandlers::new().with_modern_roots_list(
                    move |_, local, _| {
                        observed.fetch_add(1, Ordering::SeqCst);
                        *callback_owner.lock().unwrap() = Some(local);
                        cancelled.cancel();
                        Box::pin(std::future::pending())
                    },
                );
                let script = format!(
                    r#"{START}
printf '%s\n' '{}'
IFS= read -r listen || exit 85
printf '%s\n' '{}'
IFS= read -r reconcile || exit 86
case "$reconcile" in *'"method":"tasks/get"'*) ;; *) exit 87 ;; esac
printf '%s\n' '{}'
IFS= read -r cancel || exit 88
case "$cancel" in *'"method":"notifications/cancelled"'*) ;; *) exit 89 ;; esac
case "$cancel" in *'"requestId":3'*) ;; *) exit 90 ;; esac
{}
"#,
                    response(2, &input_task(1, false)),
                    ack(3, json!(["stream-task"])),
                    response(4, &input_task(2, false)),
                    finish_script(5)
                );
                let (mut client, handle) = connect_with_handlers(&cx, &script, handlers).await;
                let mut driver = handle.into_driver(drive_policy());
                assert_eq!(
                    driver
                        .drive_watching_with_stdio(&cx, &mut client, &observing)
                        .await
                        .unwrap(),
                    FinalTaskWaitOutcome::ObservationCancelled
                );
                assert!(driver.input_resolution_interrupted());
                assert!(
                    owned
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .is_cancel_requested()
                );
                let live = McpRequestCancellation::new();
                assert!(
                    driver
                        .drive_watching_with_stdio(&cx, &mut client, &live)
                        .await
                        .is_err()
                );
                assert!(
                    driver
                        .drive_with_stdio(&cx, &mut client, &live)
                        .await
                        .is_err()
                );
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                finish(&cx, &mut client).await;
            });
    }

    #[test]
    fn public_stdio_task_watch_driver_falls_back_after_empty_or_completed_listener() {
        RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            for empty in [false, true] {
                let end = if empty {
                    "IFS= read -r cancel || exit 86\ncase \"$cancel\" in *'\"requestId\":3'*) ;; *) exit 87 ;; esac\n".to_owned()
                } else {
                    format!("printf '%s\\n' '{}'\n", completion(3))
                };
                let script = format!(r#"{START}
printf '%s\n' '{}'
IFS= read -r listen || exit 85
printf '%s\n' '{}'
{end}
IFS= read -r poll || exit 88
case "$poll" in *'"method":"tasks/get"'*) ;; *) exit 89 ;; esac
printf '%s\n' '{}'
{}
"#, response(2, &task("working", None, 1)),
                    ack(3, if empty { json!([]) } else { json!(["stream-task"]) }),
                    response(4, &task("completed", None, 2)), finish_script(5));
                let (mut client, handle) = connect(&cx, &script).await;
                let mut driver = handle.into_driver(drive_policy());
                assert_eq!(driver.drive_watching_with_stdio(
                    &cx, &mut client, &McpRequestCancellation::new(),
                ).await.unwrap(), FinalTaskWaitOutcome::Completed);
                assert_completed(driver.task());
                finish(&cx, &mut client).await;
            }
        });
    }

    #[test]
    fn public_stdio_task_watch_driver_cancel_and_drop_preserve_catalog_and_foreign_listener() {
        RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            for mode in ["cancel", "drop", "foreign"] {
                let script = format!(r#"{START}
printf '%s\n' '{}'
IFS= read -r catalog || exit 85
printf '%s\n' '{{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{{"_meta":{{"io.modelcontextprotocol/subscriptionId":3}},"notifications":{{"toolsListChanged":true}}}}}}'
IFS= read -r listen || exit 86
case "$listen" in *'"id":4'*) ;; *) exit 87 ;; esac
printf '%s\n' '{}'
IFS= read -r cancel || exit 88
case "$cancel" in *'"requestId":4'*) ;; *) exit 89 ;; esac
printf '%s\n' '{{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{{"_meta":{{"io.modelcontextprotocol/subscriptionId":3}}}}}}' '{}'
{}
"#, response(2, &with_poll(&task("working", None, 1), 600_001)),
                    ack(4, json!(["stream-task"])), completion(3), finish_script(5));
                let (mut client, handle) = connect(&cx, &script).await;
                let live = McpRequestCancellation::new();
                client.open_subscriptions_listener_with_cx(&cx, &live,
                    SubscriptionFilter { tools_list_changed: Some(true), ..SubscriptionFilter::default() },
                ).await.unwrap();
                let mut driver = handle.into_driver(drive_policy());
                let before = serde_json::to_vec(driver.task()).unwrap();
                let observing = McpRequestCancellation::new();
                if mode == "foreign" {
                    client.open_final_task_subscription_listener_with_cx(&cx, &live,
                        serde_json::from_value(json!({"taskIds":["stream-task"]})).unwrap(),
                    ).await.unwrap();
                    let before_id = client.peek_next_request_id();
                    let error = driver.drive_watching_with_stdio(&cx, &mut client, &observing).await.unwrap_err();
                    assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidRequest);
                    assert_eq!(client.peek_next_request_id(), before_id);
                    assert!(matches!(client.next_final_task_subscription_event_with_cx(&cx, &live).await.unwrap(),
                        StdioTaskSubscriptionEvent::Acknowledged(_)), "the original Task listener survives rejection");
                    client.cancel_live_final_task_subscription(&cx).unwrap();
                } else {
                    let mut driving = Box::pin(driver.drive_watching_with_stdio(&cx, &mut client, &observing));
                    assert!(std::future::poll_fn(|task_cx| Poll::Ready(driving.as_mut().poll(task_cx))).await.is_pending());
                    if mode == "cancel" {
                        observing.cancel();
                        assert_eq!(driving.await.unwrap(), FinalTaskWaitOutcome::ObservationCancelled);
                    } else {
                        drop(driving);
                    }
                }
                assert_eq!(serde_json::to_vec(driver.task()).unwrap(), before);
                assert!(!driver.input_resolution_interrupted());
                assert!(matches!(client.next_subscription_event_with_cx(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Acknowledged(_)));
                assert!(matches!(client.next_subscription_event_with_cx(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Notification(_)));
                assert!(matches!(client.next_subscription_event_with_cx(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Terminal));
                finish(&cx, &mut client).await;
            }
        });
    }

    #[test]
    fn public_stdio_task_stream_watch_renews_reconciles_and_preserves_completion() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let initial = task("working", Some(live_ttl(60)), 1);
                let renewed = task("working", Some(live_ttl(120)), 2);
                let ambiguous = task("working", None, 2);
                let authoritative =
                    task("working", None, 1).replace(CREATED, "2026-07-28T00:00:00+00:00");
                let completed = task("completed", None, 3);
                let script = format!(
                    r#"{START}
printf '%s\n' '{}'
IFS= read -r listen || exit 85
case "$listen" in *'"taskIds":["stream-task"]'*) ;; *) exit 86 ;; esac
printf '%s\n' '{}' '{}' '{}' '{}'
IFS= read -r reconcile || exit 87
case "$reconcile" in *'"method":"tasks/get"'*) ;; *) exit 88 ;; esac
case "$reconcile" in *'"id":4'*) ;; *) exit 89 ;; esac
printf '%s\n' '{}' '{}' '{}'
IFS= read -r cancel || exit 90
case "$cancel" in *'"method":"notifications/cancelled"'*) ;; *) exit 91 ;; esac
case "$cancel" in *'"requestId":3'*) ;; *) exit 92 ;; esac
IFS= read -r sibling || exit 93
case "$sibling" in *'"id":5'*) ;; *) exit 94 ;; esac
printf '%s\n' '{}'
exec sleep 10
"#,
                    response(2, &initial),
                    ack(3, json!(["stream-task", "stream-task"])),
                    notification(3, &renewed),
                    notification(3, &renewed),
                    notification(3, &ambiguous),
                    response(4, &authoritative),
                    notification(3, &completed),
                    notification(3, &completed),
                    response(5, &task("cancelled", None, 4))
                );
                let (mut client, mut handle) = connect(&cx, &script).await;
                let live = McpRequestCancellation::new();
                let mut watch = handle
                    .watch_with_stdio(&cx, &mut client, &live)
                    .await
                    .unwrap();
                assert!(matches!(
                    watch.next_event(&cx, &live).await.unwrap(),
                    Some(FinalTaskWatchEvent::Acknowledged { .. })
                ));
                let Some(FinalTaskWatchEvent::TaskUpdated(renewed_event)) =
                    watch.next_event(&cx, &live).await.unwrap()
                else {
                    panic!("renewal is a live update")
                };
                assert_eq!(
                    serde_json::to_value(renewed_event).unwrap()["params"]["diagnostic"],
                    json!({"opaque":true})
                );
                assert!(watch.task().base().ttl_ms.is_some());
                let Some(FinalTaskWatchEvent::TaskReconciled {
                    observed,
                    authoritative,
                }) = watch.next_event(&cx, &live).await.unwrap()
                else {
                    panic!("one duplicate is skipped before the ambiguous update")
                };
                assert!(observed.params.task.base().ttl_ms.is_none());
                assert!(authoritative.base().ttl_ms.is_none());
                assert_eq!(
                    authoritative.base().created_at.as_str(),
                    "2026-07-28T00:00:00+00:00"
                );
                assert!(matches!(
                    watch.next_event(&cx, &live).await.unwrap(),
                    Some(FinalTaskWatchEvent::TaskUpdated(_))
                ));
                assert_completed(watch.task());
                assert_eq!(watch.stop_reason(), Some(FinalTaskWaitOutcome::Completed));
                assert!(watch.next_event(&cx, &live).await.unwrap().is_none());
                drop(watch);
                let mut terminal_watch = handle
                    .watch_with_stdio(&cx, &mut client, &live)
                    .await
                    .unwrap();
                assert!(
                    terminal_watch
                        .next_event(&cx, &live)
                        .await
                        .unwrap()
                        .is_none()
                );
                drop(terminal_watch);
                client
                    .get_task_final_with_cx(&cx, &live, handle.task_id().clone())
                    .await
                    .unwrap();
                assert_completed(handle.task());
                client.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn public_stdio_task_stream_watch_cancel_and_drop_preserve_catalog_and_next_request() {
        RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            for cancel in [true, false] {
                let script = format!(r#"{START}
printf '%s\n' '{}'
IFS= read -r catalog || exit 85
case "$catalog" in *'"id":3'*) ;; *) exit 86 ;; esac
printf '%s\n' '{{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{{"_meta":{{"io.modelcontextprotocol/subscriptionId":3}},"notifications":{{"toolsListChanged":true}}}}}}'
IFS= read -r tasks || exit 87
case "$tasks" in *'"id":4'*) ;; *) exit 88 ;; esac
printf '%s\n' '{}'
IFS= read -r cancel || exit 89
case "$cancel" in *'"method":"notifications/cancelled"'*) ;; *) exit 90 ;; esac
case "$cancel" in *'"requestId":4'*) ;; *) exit 91 ;; esac
IFS= read -r sibling || exit 92
case "$sibling" in *'"id":5'*) ;; *) exit 93 ;; esac
printf '%s\n' '{{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{{"_meta":{{"io.modelcontextprotocol/subscriptionId":3}}}}}}' '{}' '{}'
exec sleep 10
"#, response(2, &task("working", None, 1)), ack(4, json!(["stream-task"])), completion(3), response(5, &task("cancelled", None, 2)));
                let (mut client, mut handle) = connect(&cx, &script).await;
                let live = McpRequestCancellation::new();
                client.open_subscriptions_listener_with_cx(&cx, &live, SubscriptionFilter { tools_list_changed: Some(true), ..SubscriptionFilter::default() }).await.unwrap();
                let before = serde_json::to_vec(handle.task()).unwrap();
                let observing = McpRequestCancellation::new();
                let mut watch = handle.watch_with_stdio(&cx, &mut client, &observing).await.unwrap();
                assert!(matches!(watch.next_event(&cx, &observing).await.unwrap(), Some(FinalTaskWatchEvent::Acknowledged { .. })));
                let mut pending = Box::pin(watch.next_event(&cx, &observing));
                assert!(std::future::poll_fn(|context| Poll::Ready(pending.as_mut().poll(context))).await.is_pending());
                if cancel {
                    observing.cancel();
                    assert!(pending.await.unwrap().is_none());
                    assert_eq!(watch.stop_reason(), Some(FinalTaskWaitOutcome::ObservationCancelled));
                } else {
                    drop(pending);
                }
                drop(watch);
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                client.get_task_final_with_cx(&cx, &live, handle.task_id().clone()).await.unwrap();
                assert!(matches!(client.next_subscription_event_with_cx(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Acknowledged(_)));
                assert!(matches!(client.next_subscription_event_with_cx(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Notification(_)));
                assert!(matches!(client.next_subscription_event_with_cx(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Terminal));
                client.close_with_cx(&cx).await.unwrap();
            }
        });
    }

    #[test]
    fn public_stdio_task_stream_watch_accepts_empty_subset_and_refuses_rewritten_creation() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                for empty in [true, false] {
                    let initial = task("working", None, 1);
                    let forged = task("working", None, 2).replace(CREATED, "2026-07-28T00:00:01Z");
                    let script = format!(
                        r#"{START}
printf '%s\n' '{}'
IFS= read -r listen || exit 85
printf '%s\n' '{}'
{}
IFS= read -r cancel || exit 86
case "$cancel" in *'"requestId":3'*) ;; *) exit 87 ;; esac
IFS= read -r sibling || exit 88
case "$sibling" in *'"id":4'*) ;; *) exit 89 ;; esac
printf '%s\n' '{}'
exec sleep 10
"#,
                        response(2, &initial),
                        ack(
                            3,
                            if empty {
                                json!([])
                            } else {
                                json!(["stream-task"])
                            }
                        ),
                        if empty {
                            String::new()
                        } else {
                            format!("printf '%s\\n' '{}'", notification(3, &forged))
                        },
                        response(4, &task("cancelled", None, 3))
                    );
                    let (mut client, mut handle) = connect(&cx, &script).await;
                    let live = McpRequestCancellation::new();
                    let before = serde_json::to_vec(handle.task()).unwrap();
                    let mut watch = handle
                        .watch_with_stdio(&cx, &mut client, &live)
                        .await
                        .unwrap();
                    assert!(matches!(
                        watch.next_event(&cx, &live).await.unwrap(),
                        Some(FinalTaskWatchEvent::Acknowledged { .. })
                    ));
                    if empty {
                        assert!(watch.next_event(&cx, &live).await.unwrap().is_none());
                    } else {
                        assert_eq!(
                            watch.next_event(&cx, &live).await.unwrap_err().code,
                            fastmcp_core::McpErrorCode::InvalidRequest
                        );
                    }
                    drop(watch);
                    assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                    client
                        .get_task_final_with_cx(&cx, &live, handle.task_id().clone())
                        .await
                        .unwrap();
                    client.close_with_cx(&cx).await.unwrap();
                }
            });
    }
}

#[cfg(feature = "websocket-experimental")]
mod websocket {
    use super::*;
    use crate::{
        AsyncWsClientTransport, ClientBuilder, ClientProtocolPlan, ProtocolPolicy,
        RequestTimeoutPolicy, StdioSubscriptionEvent, SubscriptionTimeoutPolicy, TransportError,
    };
    use asupersync::io::AsyncWriteExt;
    use asupersync::net::tcp::VirtualTcpStream;
    use fastmcp_protocol::JsonRpcMessage;
    use fastmcp_transport::websocket::AsyncWsServerTransport;

    fn frame_bytes(source: &str) -> Vec<u8> {
        let payload = source.as_bytes();
        let mut bytes = vec![0x81];
        if payload.len() <= 125 {
            bytes.push(u8::try_from(payload.len()).unwrap());
        } else {
            bytes.push(126);
            bytes.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        }
        bytes.extend_from_slice(payload);
        bytes
    }

    async fn frame(peer: &mut VirtualTcpStream, source: &str) {
        peer.write_all(&frame_bytes(source)).await.unwrap();
    }

    async fn connect(
        cx: &Cx,
        initial: &str,
    ) -> (
        WebSocketClient<VirtualTcpStream>,
        FinalTaskHandle,
        VirtualTcpStream,
    ) {
        connect_with_handlers(cx, initial, crate::ReverseRequestHandlers::new()).await
    }

    async fn connect_with_handlers(
        cx: &Cx,
        initial: &str,
        handlers: crate::ReverseRequestHandlers,
    ) -> (
        WebSocketClient<VirtualTcpStream>,
        FinalTaskHandle,
        VirtualTcpStream,
    ) {
        let (client_io, mut peer) = VirtualTcpStream::pair(
            "127.0.0.1:45201".parse().unwrap(),
            "127.0.0.1:45202".parse().unwrap(),
        );
        frame(&mut peer, &discovery()).await;
        frame(&mut peer, &response(2, initial)).await;
        let mut client = ClientBuilder::new()
            .protocol_plan(ClientProtocolPlan::websocket(ProtocolPolicy::ModernOnly))
            .reverse_request_handlers(handlers)
            .request_timeout_policy(
                RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(2)).unwrap(),
            )
            .subscription_timeout_policy(
                SubscriptionTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(3))
                    .unwrap(),
            )
            .connect_websocket_with_cx(cx, AsyncWsClientTransport::from_upgraded(client_io))
            .await
            .unwrap();
        let handle = client
            .attach_final_task(
                cx,
                &McpRequestCancellation::new(),
                FinalTaskId::parse("stream-task").unwrap(),
            )
            .await
            .unwrap();
        (client, handle, peer)
    }

    async fn receive(
        cx: &Cx,
        peer: &mut AsyncWsServerTransport<VirtualTcpStream>,
        method: &str,
        id: Option<i64>,
    ) -> fastmcp_protocol::JsonRpcRequest {
        let JsonRpcMessage::Request(request) = peer.recv(cx).await.unwrap() else {
            panic!("expected WebSocket client request");
        };
        assert_eq!(request.method, method);
        assert_eq!(request.id, id.map(RequestId::Number));
        request
    }

    async fn send(cx: &Cx, peer: &mut AsyncWsServerTransport<VirtualTcpStream>, source: &str) {
        peer.send(cx, &serde_json::from_str(source).unwrap())
            .await
            .unwrap();
    }

    #[test]
    fn public_websocket_task_watch_driver_resolves_inputs_and_delivers_early_completion() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&calls);
            let handlers = crate::ReverseRequestHandlers::new().with_modern_roots_list(move |_, _, _| {
                observed.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(crate::FinalEmbeddedRootsListResult { roots: vec![] }) })
            });
            let (mut client, handle, peer) = connect_with_handlers(
                &cx, &task("working", None, 1), handlers,
            ).await;
            let mut server = cx.spawn(move |peer_cx| async move {
                let mut peer = AsyncWsServerTransport::from_upgraded(peer);
                receive(&peer_cx, &mut peer, "server/discover", Some(1)).await;
                receive(&peer_cx, &mut peer, "tasks/get", Some(2)).await;
                let listen = receive(&peer_cx, &mut peer, "subscriptions/listen", Some(3)).await;
                assert_eq!(listen.params.unwrap()["notifications"]["taskIds"], json!(["stream-task"]));
                send(&peer_cx, &mut peer, &ack(3, json!(["stream-task"]))).await;
                receive(&peer_cx, &mut peer, "tasks/get", Some(4)).await;
                send(&peer_cx, &mut peer, &response(4, &with_poll(&task("working", None, 1), 600_001))).await;
                send(&peer_cx, &mut peer, &notification(3, &input_task(2, false))).await;
                let update = receive(&peer_cx, &mut peer, "tasks/update", Some(5)).await;
                assert_eq!(update.params.unwrap()["inputResponses"], json!({"roots":{"roots":[]}}));
                send(&peer_cx, &mut peer, r#"{"jsonrpc":"2.0","id":5,"result":{"resultType":"complete"}}"#).await;
                send(&peer_cx, &mut peer, &notification(3, &input_task(2, false))).await;
                send(&peer_cx, &mut peer, &notification(3, &input_task(3, true))).await;
                receive(&peer_cx, &mut peer, "tasks/get", Some(6)).await;
                send(&peer_cx, &mut peer, &response(6, &input_task(3, true))).await;
                let update = receive(&peer_cx, &mut peer, "tasks/update", Some(7)).await;
                assert_eq!(update.params.unwrap()["inputResponses"], json!({"later":{"roots":[]}}));
                send(&peer_cx, &mut peer, r#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete"}}"#).await;
                receive(&peer_cx, &mut peer, "tasks/get", Some(8)).await;
                send(&peer_cx, &mut peer, &response(8, &with_poll(&task("working", None, 4), 600_001))).await;
                send(&peer_cx, &mut peer, &notification(3, &task("completed", None, 5))).await;
                let cancelled = receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                assert_eq!(cancelled.params.unwrap()["requestId"], 3);
                receive(&peer_cx, &mut peer, "tools/list", Some(9)).await;
                send(&peer_cx, &mut peer, r#"{"jsonrpc":"2.0","id":9,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#).await;
                assert!(matches!(peer.recv(&peer_cx).await, Err(TransportError::Closed)));
            }).unwrap();
            let mut driver = handle.into_driver(drive_policy());
            let live = McpRequestCancellation::new();
            assert_eq!(driver.drive_watching_with_websocket(&cx, &mut client, &live).await.unwrap(),
                FinalTaskWaitOutcome::Completed);
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert!(!driver.input_resolution_interrupted());
            let FinalTask::Completed { result, .. } = driver.task() else { panic!("notified completion expected"); };
            // The typed peer's emitted map ordering is canonical; every numeric
            // lexeme and opaque result member still survives the driver.
            assert_eq!(serde_json::to_string(result).unwrap(),
                serde_json::to_string(&serde_json::from_str::<serde_json::Value>(EXACT_RESULT).unwrap()).unwrap());
            assert_eq!(driver.drive_watching_with_websocket(&cx, &mut client, &live).await.unwrap(),
                FinalTaskWaitOutcome::Completed);
            client.list_tools(&cx, None).await.unwrap();
            client.close(&cx).await.unwrap();
            server.join(&cx).await.unwrap();
        });
    }

    #[test]
    fn public_websocket_task_watch_driver_preserves_partial_frame_across_due_poll() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let (mut client, handle, mut peer) = connect(&cx, &task("working", None, 1)).await;
                frame(&mut peer, &ack(3, json!(["stream-task"]))).await;
                let terminal = frame_bytes(&notification(3, &task("completed", None, 2)));
                let live = McpRequestCancellation::new();
                let mut driver = handle.into_driver(drive_policy());
                let mut driving =
                    Box::pin(driver.drive_watching_with_websocket(&cx, &mut client, &live));
                assert!(
                    std::future::poll_fn(|task_cx| Poll::Ready(driving.as_mut().poll(task_cx)))
                        .await
                        .is_pending()
                );
                asupersync::time::sleep(cx.now(), Duration::from_millis(80)).await;
                assert!(
                    std::future::poll_fn(|task_cx| Poll::Ready(driving.as_mut().poll(task_cx)))
                        .await
                        .is_pending()
                );
                // Settle the attach/listen reconciliation before introducing the
                // partial frame. Dropping the pending event wait for the later
                // due poll (id 5) must retain the frame begun after read id 4.
                frame(
                    &mut peer,
                    &response(4, &with_poll(&task("working", None, 1), 40)),
                )
                .await;
                peer.write_all(&terminal[..65]).await.unwrap();
                assert!(
                    std::future::poll_fn(|task_cx| Poll::Ready(driving.as_mut().poll(task_cx)))
                        .await
                        .is_pending()
                );
                asupersync::time::sleep(cx.now(), Duration::from_millis(80)).await;
                assert!(
                    std::future::poll_fn(|task_cx| Poll::Ready(driving.as_mut().poll(task_cx)))
                        .await
                        .is_pending()
                );
                peer.write_all(&terminal[65..]).await.unwrap();
                frame(
                    &mut peer,
                    &response(5, &with_poll(&task("working", None, 1), 600_001)),
                )
                .await;
                assert_eq!(driving.await.unwrap(), FinalTaskWaitOutcome::Completed);
                assert_completed(driver.task());
                finish(
                    &cx,
                    &mut client,
                    peer,
                    &[
                        ("server/discover", Some(1), None),
                        ("tasks/get", Some(2), None),
                        ("subscriptions/listen", Some(3), None),
                        ("tasks/get", Some(4), None),
                        ("tasks/get", Some(5), None),
                        ("notifications/cancelled", None, Some(3)),
                        ("tools/list", Some(6), None),
                    ],
                )
                .await;
            });
    }

    #[test]
    fn public_websocket_task_watch_driver_cancellation_preserves_uncertain_input_custody() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };

        RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let owned = Arc::new(Mutex::new(None));
            let observing = McpRequestCancellation::new();
            let cancelled = observing.clone();
            let observed = Arc::clone(&calls);
            let callback_owner = Arc::clone(&owned);
            let handlers = crate::ReverseRequestHandlers::new().with_modern_roots_list(move |_, local, _| {
                observed.fetch_add(1, Ordering::SeqCst);
                *callback_owner.lock().unwrap() = Some(local);
                cancelled.cancel();
                Box::pin(std::future::pending())
            });
            let (mut client, handle, mut peer) = connect_with_handlers(
                &cx, &input_task(1, false), handlers,
            ).await;
            frame(&mut peer, &ack(3, json!(["stream-task"]))).await;
            let mut server = cx.spawn(move |peer_cx| async move {
                let mut peer = AsyncWsServerTransport::from_upgraded(peer);
                receive(&peer_cx, &mut peer, "server/discover", Some(1)).await;
                receive(&peer_cx, &mut peer, "tasks/get", Some(2)).await;
                receive(&peer_cx, &mut peer, "subscriptions/listen", Some(3)).await;
                receive(&peer_cx, &mut peer, "tasks/get", Some(4)).await;
                send(&peer_cx, &mut peer, &response(4, &input_task(2, false))).await;
                let cancel = receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                assert_eq!(cancel.params.unwrap()["requestId"], 3);
                receive(&peer_cx, &mut peer, "tools/list", Some(5)).await;
                send(&peer_cx, &mut peer, r#"{"jsonrpc":"2.0","id":5,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#).await;
                assert!(matches!(peer.recv(&peer_cx).await, Err(TransportError::Closed)));
            }).unwrap();
            let mut driver = handle.into_driver(drive_policy());
            assert_eq!(driver.drive_watching_with_websocket(&cx, &mut client, &observing).await.unwrap(),
                FinalTaskWaitOutcome::ObservationCancelled);
            assert!(driver.input_resolution_interrupted());
            assert!(owned.lock().unwrap().as_ref().unwrap().is_cancel_requested());
            let live = McpRequestCancellation::new();
            assert!(driver.drive_watching_with_websocket(&cx, &mut client, &live).await.is_err());
            assert!(driver.drive_with_websocket(&cx, &mut client, &live).await.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            client.list_tools(&cx, None).await.unwrap();
            client.close(&cx).await.unwrap();
            server.join(&cx).await.unwrap();
        });
    }

    #[test]
    fn public_websocket_task_watch_driver_falls_back_after_empty_or_completed_listener() {
        RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            for empty in [false, true] {
                let (mut client, handle, mut peer) = connect(&cx, &task("working", None, 1)).await;
                frame(&mut peer, &ack(3, if empty { json!([]) } else { json!(["stream-task"]) })).await;
                if !empty { frame(&mut peer, &completion(3)).await; }
                let mut server = cx.spawn(move |peer_cx| async move {
                    let mut peer = AsyncWsServerTransport::from_upgraded(peer);
                    receive(&peer_cx, &mut peer, "server/discover", Some(1)).await;
                    receive(&peer_cx, &mut peer, "tasks/get", Some(2)).await;
                    receive(&peer_cx, &mut peer, "subscriptions/listen", Some(3)).await;
                    if empty {
                        let cancel = receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                        assert_eq!(cancel.params.unwrap()["requestId"], 3);
                    }
                    receive(&peer_cx, &mut peer, "tasks/get", Some(4)).await;
                    send(&peer_cx, &mut peer, &response(4, &task("completed", None, 2))).await;
                    receive(&peer_cx, &mut peer, "tools/list", Some(5)).await;
                    send(&peer_cx, &mut peer, r#"{"jsonrpc":"2.0","id":5,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#).await;
                    assert!(matches!(peer.recv(&peer_cx).await, Err(TransportError::Closed)));
                }).unwrap();
                let mut driver = handle.into_driver(drive_policy());
                assert_eq!(driver.drive_watching_with_websocket(
                    &cx, &mut client, &McpRequestCancellation::new(),
                ).await.unwrap(), FinalTaskWaitOutcome::Completed);
                client.list_tools(&cx, None).await.unwrap();
                client.close(&cx).await.unwrap();
                server.join(&cx).await.unwrap();
            }
        });
    }

    #[test]
    fn public_websocket_task_watch_driver_cancel_and_drop_preserve_catalog_and_foreign_listener() {
        RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            for mode in ["cancel", "drop", "foreign"] {
                let (mut client, handle, mut peer) = connect(&cx,
                    &with_poll(&task("working", None, 1), 600_001),
                ).await;
                client.open_subscriptions_listener(&cx,
                    SubscriptionFilter { tools_list_changed: Some(true), ..SubscriptionFilter::default() },
                ).await.unwrap();
                frame(&mut peer, r#"{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":3},"notifications":{"toolsListChanged":true}}}"#).await;
                frame(&mut peer, &ack(4, json!(["stream-task"]))).await;
                let live = McpRequestCancellation::new();
                let observing = McpRequestCancellation::new();
                let mut driver = handle.into_driver(drive_policy());
                let before = serde_json::to_vec(driver.task()).unwrap();
                if mode == "foreign" {
                    client.open_final_task_subscription_listener(&cx,
                        serde_json::from_value(json!({"taskIds":["stream-task"]})).unwrap(),
                    ).await.unwrap();
                    let before_id = client.next_id;
                    let error = driver.drive_watching_with_websocket(&cx, &mut client, &observing).await.unwrap_err();
                    assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidRequest);
                    assert_eq!(client.next_id, before_id);
                    assert!(matches!(client.next_final_task_subscription_event(&cx, &live).await.unwrap(),
                        StdioTaskSubscriptionEvent::Acknowledged(_)));
                    client.cancel_live_task_subscription().await.unwrap();
                } else {
                    let mut driving = Box::pin(driver.drive_watching_with_websocket(&cx, &mut client, &observing));
                    assert!(std::future::poll_fn(|task_cx| Poll::Ready(driving.as_mut().poll(task_cx))).await.is_pending());
                    if mode == "cancel" {
                        observing.cancel();
                        assert_eq!(driving.await.unwrap(), FinalTaskWaitOutcome::ObservationCancelled);
                    } else {
                        drop(driving);
                    }
                }
                assert_eq!(serde_json::to_vec(driver.task()).unwrap(), before);
                assert!(!driver.input_resolution_interrupted());
                frame(&mut peer, r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":3}}}"#).await;
                frame(&mut peer, &completion(3)).await;
                assert!(matches!(client.next_subscription_event(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Acknowledged(_)));
                assert!(matches!(client.next_subscription_event(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Notification(_)));
                assert!(matches!(client.next_subscription_event(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Terminal));
                finish(&cx, &mut client, peer, &[
                    ("server/discover", Some(1), None), ("tasks/get", Some(2), None),
                    ("subscriptions/listen", Some(3), None), ("subscriptions/listen", Some(4), None),
                    ("notifications/cancelled", None, Some(4)), ("tools/list", Some(5), None),
                ]).await;
            }
        });
    }

    async fn finish(
        cx: &Cx,
        client: &mut WebSocketClient<VirtualTcpStream>,
        mut peer: VirtualTcpStream,
        expected: &[(&str, Option<i64>, Option<i64>)],
    ) {
        let next_id = client.next_id;
        frame(&mut peer, &format!(r#"{{"jsonrpc":"2.0","id":{next_id},"result":{{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}}}"#)).await;
        client.list_tools(cx, None).await.unwrap();
        client.close(cx).await.unwrap();
        let mut peer = AsyncWsServerTransport::from_upgraded(peer);
        for (method, request_id, cancelled_id) in expected {
            let JsonRpcMessage::Request(request) = peer.recv(cx).await.unwrap() else {
                panic!("unexpected client response")
            };
            assert_eq!(request.method.as_str(), *method);
            assert_eq!(request.id, request_id.map(RequestId::Number));
            if let Some(id) = cancelled_id {
                assert_eq!(request.params.as_ref().unwrap()["requestId"], json!(id));
            }
            if *method == "subscriptions/listen" && *request_id == Some(3) && cancelled_id.is_none()
            {
                // The lifecycle fixture has no catalog listener.
                if let Some(ids) = request.params.as_ref().unwrap()["notifications"].get("taskIds")
                {
                    assert_eq!(ids, &json!(["stream-task"]));
                }
            }
        }
        assert!(
            matches!(peer.recv(cx).await, Err(TransportError::Closed)),
            "no implicit Task update, cancellation or retry follows"
        );
    }

    #[test]
    fn public_websocket_task_stream_watch_renews_reconciles_and_preserves_completion() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let initial = task("working", Some(live_ttl(60)), 1);
                let renewed = task("working", Some(live_ttl(120)), 2);
                let (mut client, mut handle, mut peer) = connect(&cx, &initial).await;
                for source in [
                    ack(3, json!(["stream-task", "stream-task"])),
                    notification(3, &renewed),
                    notification(3, &renewed),
                    notification(3, &task("working", None, 2)),
                    response(
                        4,
                        &task("working", None, 1).replace(CREATED, "2026-07-28T00:00:00+00:00"),
                    ),
                    notification(3, &task("completed", None, 3)),
                    notification(3, &task("completed", None, 3)),
                ] {
                    frame(&mut peer, &source).await;
                }
                let live = McpRequestCancellation::new();
                let mut watch = handle
                    .watch_with_websocket(&cx, &mut client, &live)
                    .await
                    .unwrap();
                assert!(matches!(
                    watch.next_event(&cx, &live).await.unwrap(),
                    Some(FinalTaskWatchEvent::Acknowledged { .. })
                ));
                assert!(matches!(
                    watch.next_event(&cx, &live).await.unwrap(),
                    Some(FinalTaskWatchEvent::TaskUpdated(_))
                ));
                assert!(watch.task().base().ttl_ms.is_some());
                let Some(FinalTaskWatchEvent::TaskReconciled {
                    observed,
                    authoritative,
                }) = watch.next_event(&cx, &live).await.unwrap()
                else {
                    panic!("one conflict must produce one authoritative event")
                };
                assert!(observed.params.task.base().ttl_ms.is_none());
                assert!(authoritative.base().ttl_ms.is_none());
                assert_eq!(
                    authoritative.base().created_at.as_str(),
                    "2026-07-28T00:00:00+00:00"
                );
                let Some(FinalTaskWatchEvent::TaskUpdated(completed)) =
                    watch.next_event(&cx, &live).await.unwrap()
                else {
                    panic!("terminal event")
                };
                assert_completed(&completed.params.task);
                assert_eq!(
                    serde_json::to_value(completed).unwrap()["params"]["diagnostic"],
                    json!({"opaque":true})
                );
                assert_completed(watch.task());
                assert_eq!(watch.stop_reason(), Some(FinalTaskWaitOutcome::Completed));
                assert!(watch.next_event(&cx, &live).await.unwrap().is_none());
                drop(watch);
                let mut terminal_watch = handle
                    .watch_with_websocket(&cx, &mut client, &live)
                    .await
                    .unwrap();
                assert!(
                    terminal_watch
                        .next_event(&cx, &live)
                        .await
                        .unwrap()
                        .is_none()
                );
                drop(terminal_watch);
                finish(
                    &cx,
                    &mut client,
                    peer,
                    &[
                        ("server/discover", Some(1), None),
                        ("tasks/get", Some(2), None),
                        ("subscriptions/listen", Some(3), None),
                        ("tasks/get", Some(4), None),
                        ("notifications/cancelled", None, Some(3)),
                        ("tools/list", Some(5), None),
                    ],
                )
                .await;
                assert_completed(handle.task());
            });
    }

    #[test]
    fn public_websocket_task_stream_watch_cancel_and_drop_isolate_owned_requests() {
        RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            for mode in ["cancel", "drop", "drop-reconciliation"] {
                let (mut client, mut handle, mut peer) = connect(&cx, &task("working", None, 1)).await;
                client.open_subscriptions_listener(&cx, SubscriptionFilter { tools_list_changed: Some(true), ..SubscriptionFilter::default() }).await.unwrap();
                frame(&mut peer, r#"{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":3},"notifications":{"toolsListChanged":true}}}"#).await;
                frame(&mut peer, &ack(4, json!(["stream-task"]))).await;
                if mode == "drop-reconciliation" {
                    let ambiguous = task("working", Some(live_ttl(60)), 1);
                    frame(&mut peer, &notification(4, &ambiguous)).await;
                }
                let live = McpRequestCancellation::new();
                let observing = McpRequestCancellation::new();
                let before = serde_json::to_vec(handle.task()).unwrap();
                let mut watch = handle.watch_with_websocket(&cx, &mut client, &observing).await.unwrap();
                assert!(matches!(watch.next_event(&cx, &observing).await.unwrap(), Some(FinalTaskWatchEvent::Acknowledged { .. })));
                let mut pending = Box::pin(watch.next_event(&cx, &observing));
                assert!(std::future::poll_fn(|context| Poll::Ready(pending.as_mut().poll(context))).await.is_pending());
                if mode == "cancel" {
                    observing.cancel();
                    assert!(pending.await.unwrap().is_none());
                    assert_eq!(watch.stop_reason(), Some(FinalTaskWaitOutcome::ObservationCancelled));
                } else {
                    drop(pending);
                }
                drop(watch);
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                let mut trace = vec![
                    ("server/discover", Some(1), None), ("tasks/get", Some(2), None),
                    ("subscriptions/listen", Some(3), None), ("subscriptions/listen", Some(4), None),
                ];
                if mode == "drop-reconciliation" {
                    trace.extend([("tasks/get", Some(5), None), ("notifications/cancelled", None, Some(5))]);
                    frame(&mut peer, &response(5, &task("completed", None, 2))).await;
                }
                trace.push(("notifications/cancelled", None, Some(4)));
                frame(&mut peer, r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":3}}}"#).await;
                frame(&mut peer, &completion(3)).await;
                // Driving the catalog retires only the abandoned Task owners,
                // then delivers the independent catalog acknowledgement/data.
                assert!(matches!(client.next_subscription_event(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Acknowledged(_)));
                assert!(matches!(client.next_subscription_event(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Notification(_)));
                assert!(matches!(client.next_subscription_event(&cx, &live).await.unwrap(), StdioSubscriptionEvent::Terminal));
                trace.push(("tools/list", Some(if mode == "drop-reconciliation" { 6 } else { 5 }), None));
                finish(&cx, &mut client, peer, &trace).await;
            }
        });
    }

    #[test]
    fn public_websocket_task_stream_watch_empty_completion_and_identity_admission() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                for mode in [
                    "empty",
                    "completed-listen",
                    "changed-creation",
                    "cancelled-before-open",
                    "expired-before-open",
                    "expires-during-watch",
                ] {
                    let initial = task(
                        "working",
                        match mode {
                            "expired-before-open" => Some(1),
                            "expires-during-watch" => Some(live_ttl(1)),
                            _ => None,
                        },
                        1,
                    );
                    let (mut client, mut handle, mut peer) = connect(&cx, &initial).await;
                    let observing = McpRequestCancellation::new();
                    if mode == "cancelled-before-open" {
                        observing.cancel();
                    }
                    let before = serde_json::to_vec(handle.task()).unwrap();
                    let mut trace = vec![
                        ("server/discover", Some(1), None),
                        ("tasks/get", Some(2), None),
                    ];
                    let opens = !mode.ends_with("before-open");
                    if opens {
                        frame(
                            &mut peer,
                            &ack(
                                3,
                                if mode == "empty" {
                                    json!([])
                                } else {
                                    json!(["stream-task"])
                                },
                            ),
                        )
                        .await;
                        trace.push(("subscriptions/listen", Some(3), None));
                        if mode == "changed-creation" {
                            frame(
                                &mut peer,
                                &notification(
                                    3,
                                    &task("working", None, 2)
                                        .replace(CREATED, "2026-07-28T00:00:01Z"),
                                ),
                            )
                            .await;
                        }
                        if mode == "completed-listen" {
                            frame(&mut peer, &completion(3)).await;
                        }
                    }
                    let mut watch = handle
                        .watch_with_websocket(&cx, &mut client, &observing)
                        .await
                        .unwrap();
                    if opens {
                        assert!(matches!(
                            watch.next_event(&cx, &observing).await.unwrap(),
                            Some(FinalTaskWatchEvent::Acknowledged { .. })
                        ));
                    }
                    if mode == "changed-creation" {
                        assert_eq!(
                            watch.next_event(&cx, &observing).await.unwrap_err().code,
                            fastmcp_core::McpErrorCode::InvalidRequest
                        );
                    } else {
                        assert!(watch.next_event(&cx, &observing).await.unwrap().is_none());
                    }
                    if !opens || mode == "expires-during-watch" {
                        assert_eq!(
                            watch.stop_reason(),
                            Some(if mode.contains("expire") {
                                FinalTaskWaitOutcome::TaskExpired
                            } else {
                                FinalTaskWaitOutcome::ObservationCancelled
                            })
                        );
                    }
                    drop(watch);
                    assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                    if opens && mode != "completed-listen" {
                        trace.push(("notifications/cancelled", None, Some(3)));
                    }
                    trace.push(("tools/list", Some(if opens { 4 } else { 3 }), None));
                    finish(&cx, &mut client, peer, &trace).await;
                }
            });
    }

    #[test]
    fn public_websocket_dropped_task_watch_cannot_deliver_a_queued_terminal_owner() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let (mut client, mut handle, mut peer) =
                    connect(&cx, &task("working", None, 1)).await;
                let live = McpRequestCancellation::new();
                for source in [
                    ack(3, json!(["stream-task"])),
                    notification(3, &task("working", Some(live_ttl(60)), 1)),
                    completion(3),
                    response(4, &task("working", None, 2)),
                ] {
                    frame(&mut peer, &source).await;
                }
                let mut watch = handle
                    .watch_with_websocket(&cx, &mut client, &live)
                    .await
                    .unwrap();
                assert!(matches!(
                    watch.next_event(&cx, &live).await.unwrap(),
                    Some(FinalTaskWatchEvent::Acknowledged { .. })
                ));
                assert!(matches!(
                    watch.next_event(&cx, &live).await.unwrap(),
                    Some(FinalTaskWatchEvent::TaskReconciled { .. })
                ));
                drop(watch);
                let error = client
                    .next_final_task_subscription_event(&cx, &live)
                    .await
                    .expect_err("the dropped watch's queued terminal must not regain an observer");
                assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidRequest);
                assert!(client.live_task_subscription.is_none());
                finish(
                    &cx,
                    &mut client,
                    peer,
                    &[
                        ("server/discover", Some(1), None),
                        ("tasks/get", Some(2), None),
                        ("subscriptions/listen", Some(3), None),
                        ("tasks/get", Some(4), None),
                        ("notifications/cancelled", None, Some(3)),
                        ("tools/list", Some(5), None),
                    ],
                )
                .await;
            });
    }
}
