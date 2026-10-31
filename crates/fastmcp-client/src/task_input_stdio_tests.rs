//! Public Unix subprocess tests for explicit input submission and reconciliation.
//! The shell peer refuses duplicate updates and unrequested remote cancellation.

use super::*;
use crate::{ClientBuilder, ClientProtocolPlan, ProtocolPolicy, RequestTimeoutPolicy};
use fastmcp_core::McpErrorCode;
use serde_json::{Value, json};

const DISCOVERY: &str = r#"
IFS= read -r discovery || exit 81
case "$discovery" in *'"method":"server/discover"'*) ;; *) exit 82 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"extensions":{"io.modelcontextprotocol/tasks":{}}},"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"input-peer","version":"1"}}}}'
IFS= read -r attach || exit 83
case "$attach" in *'"id":2'*) ;; *) exit 84 ;; esac
case "$attach" in *'"method":"tasks/get"'*) ;; *) exit 85 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","taskId":"input-task","status":"input_required","createdAt":"2026-07-28T00:00:00Z","lastUpdatedAt":"2026-07-28T00:00:01Z","ttlMs":null,"inputRequests":{"roots":{"method":"roots/list"}}}}'
"#;

const UPDATE: &str = r#"
IFS= read -r update || exit 86
case "$update" in *'"id":3'*) ;; *) exit 87 ;; esac
case "$update" in *'"method":"tasks/update"'*) ;; *) exit 88 ;; esac
case "$update" in *'"taskId":"input-task"'*) ;; *) exit 89 ;; esac
case "$update" in *'"inputResponses":{"roots":{"roots":[]}}'*) ;; *) exit 90 ;; esac
case "$update" in *'"io.modelcontextprotocol/tasks":{}'*) ;; *) exit 91 ;; esac
"#;

const RECONCILE: &str = r#"
IFS= read -r reconcile || exit 92
case "$reconcile" in *'"id":4'*) ;; *) exit 93 ;; esac
case "$reconcile" in *'"method":"tasks/get"'*) ;; *) exit 94 ;; esac
case "$reconcile" in *'"taskId":"input-task"'*) ;; *) exit 95 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete","taskId":"input-task","status":"completed","createdAt":"2026-07-28T00:00:00+00:00","lastUpdatedAt":"2026-07-28T00:00:02Z","ttlMs":null,"result":{"content":[{"type":"text","text":"resumed"}],"futurePayload":{"kept":true}}}}'
"#;

fn sentinel(id: u64) -> String {
    format!(
        r#"
while IFS= read -r next; do
    case "$next" in *'"method":"notifications/cancelled"'*) continue ;; esac
    break
done
case "$next" in *'"id":{id}'*) ;; *) exit 96 ;; esac
case "$next" in *'"method":"tasks/get"'*) ;; *) exit 97 ;; esac
case "$next" in *'"taskId":"sentinel"'*) ;; *) exit 98 ;; esac
printf '%s\n' '{{"jsonrpc":"2.0","id":{id},"result":{{"resultType":"complete","taskId":"sentinel","status":"cancelled","createdAt":"2026-07-28T00:00:00Z","lastUpdatedAt":"2026-07-28T00:00:02Z","ttlMs":null}}}}'
exec sleep 10
"#
    )
}

async fn connect(cx: &Cx, script: &str) -> (Client, FinalTaskHandle) {
    let mut client = ClientBuilder::new()
        .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
        .capabilities(fastmcp_protocol::ClientCapabilities {
            roots: Some(Default::default()),
            ..fastmcp_protocol::ClientCapabilities::default()
        })
        .request_timeout_policy(
            RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(2)).unwrap(),
        )
        .connect_stdio_with_cx(cx, "sh", &["-c", script])
        .await
        .unwrap();
    let handle = client
        .attach_final_task_with_cx(
            cx,
            &McpRequestCancellation::new(),
            FinalTaskId::parse("input-task").unwrap(),
        )
        .await
        .unwrap();
    (client, handle)
}

async fn finish(cx: &Cx, client: &mut Client) {
    let result = client
        .get_task_final_with_cx(
            cx,
            &McpRequestCancellation::new(),
            FinalTaskId::parse("sentinel").unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(result.task, FinalTask::Cancelled(_)));
    client.close_with_cx(cx).await.unwrap();
    assert!(cx.checkpoint().is_ok());
}

fn answers(value: Value) -> FinalTaskInputResponses {
    serde_json::from_value(value).unwrap()
}

#[test]
fn public_stdio_input_acknowledgement_requires_authoritative_reconciliation() {
    asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let script = format!(
            "{DISCOVERY}{UPDATE}{}{RECONCILE}{}",
            "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resultType\":\"complete\"}}'\n",
            sentinel(5),
        );
        let (mut client, mut handle) = connect(&cx, &script).await;
        let cancellation = McpRequestCancellation::new();
        let before = serde_json::to_vec(handle.task()).unwrap();
        handle.resume_input_with_stdio(
            &cx, &mut client, &cancellation, answers(json!({"roots":{"roots":[]}})),
        ).await.unwrap();
        assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before,
            "an acknowledgement must not fabricate a working/completed Task");
        handle.poll_with_stdio(&cx, &mut client, &cancellation).await.unwrap();
        let result = serde_json::to_value(handle.task()).unwrap();
        assert_eq!(result["status"], "completed");
        assert_eq!(result["result"]["futurePayload"], json!({"kept":true}));
        assert_eq!(result["createdAt"], "2026-07-28T00:00:00+00:00");
        assert_eq!(handle.wait_with_stdio(
            &cx, &mut client, &cancellation, FinalTaskWaitPolicy::default(),
        ).await.unwrap(), FinalTaskWaitOutcome::Completed);
        let terminal = serde_json::to_vec(handle.task()).unwrap();
        let next_id = client.peek_next_request_id();
        handle.poll_with_stdio(&cx, &mut client, &cancellation).await.unwrap();
        assert_eq!(serde_json::to_vec(handle.task()).unwrap(), terminal,
            "an already observed terminal result cannot be replaced by another poll");
        assert_eq!(client.peek_next_request_id(), next_id,
            "terminal reconciliation must not allocate or send a request");
        finish(&cx, &mut client).await;
    });
}

#[test]
fn public_stdio_input_rejects_bad_phase_kind_and_expiry_without_spending_an_id() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let script = format!("{DISCOVERY}{}", sentinel(3));
            let (mut client, mut handle) = connect(&cx, &script).await;
            let before = serde_json::to_vec(handle.task()).unwrap();
            let cancellation = McpRequestCancellation::new();
            let next_id = client.peek_next_request_id();
            let wrong_handle_kind = handle
                .resume_input_with_stdio(
                    &cx,
                    &mut client,
                    &cancellation,
                    answers(json!({"roots":{"action":"accept"}})),
                )
                .await
                .unwrap_err();
            assert_eq!(wrong_handle_kind.code, McpErrorCode::InvalidParams);
            let wrong_kind = client
                .update_task_final_with_cx(
                    &cx,
                    &cancellation,
                    handle.task(),
                    answers(json!({"roots":{"action":"accept"}})),
                )
                .await
                .unwrap_err();
            assert_eq!(wrong_kind.code, McpErrorCode::InvalidParams);
            for status in ["working", "completed", "cancelled"] {
                let mut value = serde_json::to_value(handle.task()).unwrap();
                value["status"] = json!(status);
                value.as_object_mut().unwrap().remove("inputRequests");
                if status == "completed" {
                    value["result"] = json!({"content":[]});
                }
                let task: FinalTask = serde_json::from_str(&value.to_string()).unwrap();
                let error = client
                    .update_task_final_with_cx(
                        &cx,
                        &cancellation,
                        &task,
                        answers(json!({"roots":{"roots":[]}})),
                    )
                    .await
                    .unwrap_err();
                assert_eq!(error.code, McpErrorCode::InvalidParams);
            }
            let mut value = serde_json::to_value(handle.task()).unwrap();
            value["createdAt"] = json!("1970-01-01T00:00:00Z");
            value["ttlMs"] = json!(1);
            let expired: FinalTask = serde_json::from_str(&value.to_string()).unwrap();
            let error = client
                .update_task_final_with_cx(
                    &cx,
                    &cancellation,
                    &expired,
                    answers(json!({"roots":{"roots":[]}})),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, McpErrorCode::InvalidRequest);
            assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
            assert!(!cancellation.is_cancel_requested());
            assert_eq!(
                client.peek_next_request_id(),
                next_id,
                "local input rejection must leave the shared request ID allocator unchanged"
            );
            finish(&cx, &mut client).await;
        });
}

#[test]
fn public_stdio_precancelled_input_flush_and_reconciliation_have_no_wire_effect() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let script = format!("{DISCOVERY}{}", sentinel(3));
            let (mut client, mut handle) = connect(&cx, &script).await;
            let before = serde_json::to_vec(handle.task()).unwrap();
            let cancellation = McpRequestCancellation::new();
            cancellation.cancel();
            let error = handle
                .resume_input_with_stdio(
                    &cx,
                    &mut client,
                    &cancellation,
                    answers(json!({"roots":{"roots":[]}})),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, McpErrorCode::RequestCancelled);
            let error = handle
                .poll_with_stdio(&cx, &mut client, &cancellation)
                .await
                .unwrap_err();
            assert_eq!(error.code, McpErrorCode::RequestCancelled);
            assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
            finish(&cx, &mut client).await;
        });
}

#[test]
fn public_stdio_failed_input_update_is_not_replayed_or_promoted_to_a_snapshot() {
    for malformed in [false, true] {
        let reply = if malformed {
            r#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"input_required"}}"#
        } else {
            r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"stale input"}}"#
        };
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let script = format!(
                    "{DISCOVERY}{UPDATE}printf '%s\\n' '{reply}'\n{}",
                    sentinel(4)
                );
                let (mut client, mut handle) = connect(&cx, &script).await;
                let before = serde_json::to_vec(handle.task()).unwrap();
                let cancellation = McpRequestCancellation::new();
                let error = handle
                    .resume_input_with_stdio(
                        &cx,
                        &mut client,
                        &cancellation,
                        answers(json!({"roots":{"roots":[]}})),
                    )
                    .await
                    .unwrap_err();
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                assert!(!cancellation.is_cancel_requested());
                assert_eq!(
                    client.peek_next_request_id(),
                    4,
                    "a failed or malformed acknowledgement must not replay the update"
                );
                if malformed {
                    assert_eq!(error.code, McpErrorCode::InvalidRequest);
                    assert!(
                        client.transport_is_closed(),
                        "a peer violating the typed control result must close the connection"
                    );
                    client.close_with_cx(&cx).await.unwrap();
                } else {
                    assert_eq!(error.code, McpErrorCode::InvalidParams);
                    finish(&cx, &mut client).await;
                }
            });
    }
}

#[test]
fn public_stdio_reconciliation_preserves_identity_and_accepts_retention_changes() {
    for field in ["taskId", "createdAt", "ttlMs"] {
        asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let mut task = json!({
                "resultType":"complete","taskId":"input-task","status":"working",
                "createdAt":"2026-07-28T00:00:00Z","lastUpdatedAt":"2026-07-28T00:00:02Z","ttlMs":null
            });
            task[field] = match field {
                "taskId" => json!("other-task"),
                "createdAt" => json!("2026-07-28T00:00:01Z"),
                _ => json!(u64::MAX),
            };
            let response = json!({"jsonrpc":"2.0","id":3,"result":task});
            let script = format!("{DISCOVERY}{}\nprintf '%s\\n' '{response}'\n{}", r#"
IFS= read -r poll || exit 86
case "$poll" in *'"id":3'*) ;; *) exit 87 ;; esac
case "$poll" in *'"method":"tasks/get"'*) ;; *) exit 88 ;; esac
"#, sentinel(4));
            let (mut client, mut handle) = connect(&cx, &script).await;
            let before = serde_json::to_vec(handle.task()).unwrap();
            let cancellation = McpRequestCancellation::new();
            let result = handle.poll_with_stdio(&cx, &mut client, &cancellation).await;
            if field == "ttlMs" {
                let task = result.unwrap();
                assert!(matches!(task, FinalTask::Working(_)));
                assert_eq!(task.base().ttl_ms.as_ref().unwrap().try_as_millis().unwrap(), u64::MAX);
                assert_eq!(task.base().created_at.as_str(), "2026-07-28T00:00:00Z");
            } else {
                assert!(result.is_err());
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
            }
            if field == "taskId" {
                assert!(client.transport_is_closed(),
                    "the typed Tasks decoder must reject a response for another Task");
                client.close_with_cx(&cx).await.unwrap();
            } else {
                finish(&cx, &mut client).await;
            }
        });
    }
}

#[test]
fn public_stdio_pending_input_update_can_be_cancelled_or_abandoned_without_replay() {
    for abandon in [false, true] {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                // The update is consumed but no ACK is sent. Only request-local
                // notifications may precede the subsequent independent Task read.
                let script = format!("{DISCOVERY}{UPDATE}{}", sentinel(4));
                let (mut client, mut handle) = connect(&cx, &script).await;
                let before = serde_json::to_vec(handle.task()).unwrap();
                let cancellation = McpRequestCancellation::new();
                let mut update = Box::pin(handle.resume_input_with_stdio(
                    &cx,
                    &mut client,
                    &cancellation,
                    answers(json!({"roots":{"roots":[]}})),
                ));
                std::future::poll_fn(|task| {
                    assert!(
                        update.as_mut().poll(task).is_pending(),
                        "peer withholds acknowledgement"
                    );
                    Poll::Ready(())
                })
                .await;
                if !abandon {
                    cancellation.cancel();
                    assert_eq!(
                        update.as_mut().await.unwrap_err().code,
                        McpErrorCode::RequestCancelled
                    );
                }
                drop(update);
                assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                assert_eq!(cancellation.is_cancel_requested(), !abandon);
                finish(&cx, &mut client).await;
            });
    }
}

#[test]
fn public_stdio_input_preflight_rejects_before_deferred_discovery() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let script = format!("{DISCOVERY}{}", sentinel(3));
            let mut client = ClientBuilder::new()
                .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
                .auto_initialize(true)
                .request_timeout_policy(
                    RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(2))
                        .unwrap(),
                )
                .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
                .await
                .unwrap();
            let value = json!({
                "taskId":"input-task", "status":"input_required",
                "createdAt":"2026-07-28T00:00:00Z",
                "lastUpdatedAt":"2026-07-28T00:00:01Z", "ttlMs":null,
                "inputRequests":{"roots":{"method":"roots/list"}}
            });
            let task: FinalTask = serde_json::from_str(&value.to_string()).unwrap();
            let cancellation = McpRequestCancellation::new();
            let before_id = client.peek_next_request_id();
            assert!(!client.is_initialized());
            let error = client
                .update_task_final_with_cx(
                    &cx,
                    &cancellation,
                    &task,
                    answers(json!({"roots":{"action":"accept"}})),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, McpErrorCode::InvalidParams);
            let mut expired = value.clone();
            expired["createdAt"] = json!("1970-01-01T00:00:00Z");
            expired["ttlMs"] = json!(1);
            let expired: FinalTask = serde_json::from_str(&expired.to_string()).unwrap();
            let error = client
                .update_task_final_with_cx(
                    &cx,
                    &cancellation,
                    &expired,
                    answers(json!({"roots":{"roots":[]}})),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, McpErrorCode::InvalidRequest);
            let cancelled = McpRequestCancellation::new();
            cancelled.cancel();
            let error = client
                .update_task_final_with_cx(
                    &cx,
                    &cancelled,
                    &task,
                    answers(json!({"roots":{"roots":[]}})),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, McpErrorCode::RequestCancelled);
            assert!(
                !client.is_initialized(),
                "invalid local input cannot send discovery"
            );
            assert_eq!(
                client.peek_next_request_id(),
                before_id,
                "preflight rejection must not allocate even the initialization request"
            );
            let handle = client
                .attach_final_task_with_cx(
                    &cx,
                    &cancellation,
                    FinalTaskId::parse("input-task").unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(serde_json::to_value(handle.task()).unwrap(), value);
            finish(&cx, &mut client).await;
        });
}

#[test]
fn public_stdio_partial_input_requires_explicit_reconciliation_and_next_submission() {
    asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let discovery = DISCOVERY.replace(
            r#""inputRequests":{"roots":{"method":"roots/list"}}"#,
            r#""inputRequests":{"roots":{"method":"roots/list"},"more-roots":{"method":"roots/list"}}"#,
        );
        assert_ne!(discovery, DISCOVERY);
        let script = format!("{discovery}{UPDATE}{}{}", r#"
case "$update" in *'more-roots'*) exit 101 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete"}}'
IFS= read -r poll || exit 102
case "$poll" in *'"id":4'*) ;; *) exit 103 ;; esac
case "$poll" in *'"method":"tasks/get"'*) ;; *) exit 104 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete","taskId":"input-task","status":"input_required","createdAt":"2026-07-28T00:00:00Z","lastUpdatedAt":"2026-07-28T00:00:02Z","ttlMs":null,"inputRequests":{"more-roots":{"method":"roots/list"}}}}'
IFS= read -r update || exit 105
case "$update" in *'"id":5'*) ;; *) exit 106 ;; esac
case "$update" in *'"method":"tasks/update"'*) ;; *) exit 107 ;; esac
case "$update" in *'"inputResponses":{"more-roots":{"roots":[]}}'*) ;; *) exit 108 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":5,"result":{"resultType":"complete"}}'
IFS= read -r poll || exit 109
case "$poll" in *'"id":6'*) ;; *) exit 110 ;; esac
case "$poll" in *'"method":"tasks/get"'*) ;; *) exit 111 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":6,"result":{"resultType":"complete","taskId":"input-task","status":"completed","createdAt":"2026-07-28T00:00:00Z","lastUpdatedAt":"2026-07-28T00:00:03Z","ttlMs":null,"result":{"content":[{"type":"text","text":"both inputs accepted"}]}}}'
"#, sentinel(7));
        let (mut client, mut handle) = connect(&cx, &script).await;
        let cancellation = McpRequestCancellation::new();
        let before = serde_json::to_vec(handle.task()).unwrap();
        handle.resume_input_with_stdio(
            &cx, &mut client, &cancellation, answers(json!({"roots":{"roots":[]}})),
        ).await.unwrap();
        assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before,
            "the first partial acknowledgement cannot erase outstanding input");
        handle.poll_with_stdio(&cx, &mut client, &cancellation).await.unwrap();
        let input_required = serde_json::to_value(handle.task()).unwrap();
        assert_eq!(input_required["inputRequests"], json!({"more-roots":{"method":"roots/list"}}));
        assert_eq!(handle.wait_with_stdio(
            &cx, &mut client, &cancellation, FinalTaskWaitPolicy::default(),
        ).await.unwrap(), FinalTaskWaitOutcome::InputRequired,
            "waiting must pause instead of resolving or resubmitting the remaining input");
        assert_eq!(client.peek_next_request_id(), 5);
        handle.resume_input_with_stdio(
            &cx, &mut client, &cancellation, answers(json!({"more-roots":{"roots":[]}})),
        ).await.unwrap();
        assert_eq!(serde_json::to_value(handle.task()).unwrap(), input_required);
        handle.poll_with_stdio(&cx, &mut client, &cancellation).await.unwrap();
        assert!(matches!(handle.task(), FinalTask::Completed { .. }));
        finish(&cx, &mut client).await;
    });
}
