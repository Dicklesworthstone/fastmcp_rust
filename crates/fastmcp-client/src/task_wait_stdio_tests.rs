//! Public Unix stdio coverage for bounded final Task observation.

use std::future::Future;
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use serde_json::json;

use crate::{
    Client, ClientBuilder, ClientProtocolPlan, FinalTask, FinalTaskId, FinalTaskWaitOutcome,
    FinalTaskWaitPolicy, RequestTimeoutPolicy,
};

async fn connect(cx: &Cx, script: &str) -> Client {
    ClientBuilder::new()
        .protocol_plan(ClientProtocolPlan::stdio(
            fastmcp_protocol::protocol_policy::ProtocolPolicy::ModernOnly,
        ))
        .request_timeout_policy(
            RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(2)).unwrap(),
        )
        .connect_stdio_with_cx(cx, "sh", &["-c", script])
        .await
        .unwrap()
}

const DISCOVERY: &str = r#"
IFS= read -r discovery || exit 81
case "$discovery" in *'"method":"server/discover"'*) ;; *) exit 82 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"extensions":{"io.modelcontextprotocol/tasks":{}}},"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"task-wait-peer","version":"1"}}}}'
"#;

const SENTINEL: &str = r#"
case "$sentinel" in *'"method":"tasks/get"'*'"taskId":"sentinel"'*|*'"taskId":"sentinel"'*'"method":"tasks/get"'*) ;; *) exit 93 ;; esac
"#;

#[test]
fn public_stdio_task_wait_preserves_completed_result_and_stops_polling() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let script = format!(
            "{DISCOVERY}{}",
            r#"
IFS= read -r attach || exit 83
case "$attach" in *'"id":2'*) ;; *) exit 84 ;; esac
case "$attach" in *'"method":"tasks/get"'*) ;; *) exit 85 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","taskId":"observed","status":"working","createdAt":"2026-07-28T12:00:00Z","lastUpdatedAt":"2026-07-28T12:00:00Z","ttlMs":null,"pollIntervalMs":1}}'
IFS= read -r next || exit 86
case "$next" in *'"id":3'*) ;; *) exit 87 ;; esac
case "$next" in *'"method":"tasks/get"'*) ;; *) exit 88 ;; esac
case "$next" in *'"taskId":"observed"'*) ;; *) exit 89 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","taskId":"observed","status":"completed","createdAt":"2026-07-28T12:00:00+00:00","lastUpdatedAt":"2026-07-28T12:00:00Z","ttlMs":null,"result":{"content":[{"type":"text","text":"stdio complete"}],"futurePayload":{"nested":[1,true,null]}}}}'
IFS= read -r sentinel || exit 90
case "$sentinel" in *'"id":4'*) ;; *) exit 91 ;; esac
case "$sentinel" in *'"taskId":"sentinel"'*) ;; *) exit 92 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete","taskId":"sentinel","status":"cancelled","createdAt":"2026-07-28T12:00:00Z","lastUpdatedAt":"2026-07-28T12:00:01Z","ttlMs":null}}'
exec sleep 10
"#
        );
        let mut client = connect(&cx, &script).await;
        let cancellation = McpRequestCancellation::new();
        let mut handle = client
            .attach_final_task_with_cx(
                &cx,
                &cancellation,
                FinalTaskId::parse("observed").unwrap(),
            )
            .await
            .unwrap();
        let policy = FinalTaskWaitPolicy::new(
            Duration::from_secs(1),
            3,
            Duration::from_millis(5),
        )
        .unwrap();
        assert_eq!(
            handle
                .wait_with_stdio(&cx, &mut client, &cancellation, policy)
                .await
                .unwrap(),
            FinalTaskWaitOutcome::Completed
        );
        let retained = serde_json::to_value(handle.task()).unwrap();
        assert_eq!(
            retained["result"]["futurePayload"],
            json!({"nested":[1,true,null]})
        );
        assert_eq!(
            retained["createdAt"],
            "2026-07-28T12:00:00+00:00",
            "equivalent instants retain their peer lexeme"
        );
        assert_eq!(
            handle
                .wait_with_stdio(&cx, &mut client, &cancellation, policy)
                .await
                .unwrap(),
            FinalTaskWaitOutcome::Completed,
            "a retained terminal result must not issue another read"
        );
        let sentinel = client
            .get_task_final_with_cx(
                &cx,
                &cancellation,
                FinalTaskId::parse("sentinel").unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(sentinel.task, FinalTask::Cancelled(_)));
        client.close_with_cx(&cx).await.unwrap();
    });
}

#[test]
fn public_stdio_task_wait_deadline_and_precancellation_do_not_poll_early() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        for cancelled in [false, true] {
            let cx = Cx::current().unwrap();
            let script = format!(
                "{DISCOVERY}{}{SENTINEL}{}",
                r#"
IFS= read -r attach || exit 83
case "$attach" in *'"id":2'*) ;; *) exit 84 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","taskId":"observed","status":"working","createdAt":"2026-07-28T12:00:00Z","lastUpdatedAt":"2026-07-28T12:00:00Z","ttlMs":null,"pollIntervalMs":300001}}'
IFS= read -r sentinel || exit 85
case "$sentinel" in *'"id":3'*) ;; *) exit 86 ;; esac
"#,
                r#"
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","taskId":"sentinel","status":"cancelled","createdAt":"2026-07-28T12:00:00Z","lastUpdatedAt":"2026-07-28T12:00:01Z","ttlMs":null}}'
exec sleep 10
"#
            );
            let mut client = connect(&cx, &script).await;
            let cancellation = McpRequestCancellation::new();
            let mut handle = client
                .attach_final_task_with_cx(
                    &cx,
                    &cancellation,
                    FinalTaskId::parse("observed").unwrap(),
                )
                .await
                .unwrap();
            let before = serde_json::to_vec(handle.task()).unwrap();
            if cancelled {
                cancellation.cancel();
            }
            let outcome = handle
                .wait_with_stdio(
                    &cx,
                    &mut client,
                    &cancellation,
                    FinalTaskWaitPolicy::new(
                        Duration::from_millis(30),
                        8,
                        Duration::from_millis(1),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                outcome,
                if cancelled {
                    FinalTaskWaitOutcome::ObservationCancelled
                } else {
                    FinalTaskWaitOutcome::DeadlineElapsed
                }
            );
            assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
            let sentinel = client
                .get_task_final_with_cx(
                    &cx,
                    &McpRequestCancellation::new(),
                    FinalTaskId::parse("sentinel").unwrap(),
                )
                .await
                .unwrap();
            assert!(matches!(sentinel.task, FinalTask::Cancelled(_)));
            client.close_with_cx(&cx).await.unwrap();
        }
    });
}

#[test]
fn public_stdio_task_wait_cancellation_during_delay_keeps_client_usable() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let script = format!(
            "{DISCOVERY}{}{SENTINEL}{}",
            r#"
IFS= read -r attach || exit 83
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","taskId":"observed","status":"working","createdAt":"2026-07-28T12:00:00Z","lastUpdatedAt":"2026-07-28T12:00:00Z","ttlMs":null,"pollIntervalMs":300001}}'
IFS= read -r sentinel || exit 84
case "$sentinel" in *'"id":3'*) ;; *) exit 85 ;; esac
"#,
            r#"
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","taskId":"sentinel","status":"cancelled","createdAt":"2026-07-28T12:00:00Z","lastUpdatedAt":"2026-07-28T12:00:01Z","ttlMs":null}}'
exec sleep 10
"#
        );
        let mut client = connect(&cx, &script).await;
        let cancellation = McpRequestCancellation::new();
        let mut handle = client
            .attach_final_task_with_cx(
                &cx,
                &cancellation,
                FinalTaskId::parse("observed").unwrap(),
            )
            .await
            .unwrap();
        let before = serde_json::to_vec(handle.task()).unwrap();
        let policy =
            FinalTaskWaitPolicy::new(Duration::from_secs(1), 8, Duration::from_millis(1))
                .unwrap();
        let outcome = {
            let mut wait = std::pin::pin!(
                handle.wait_with_stdio(&cx, &mut client, &cancellation, policy)
            );
            let mut cancel_at = std::pin::pin!(asupersync::time::sleep(
                cx.now(),
                Duration::from_millis(10),
            ));
            std::future::poll_fn(|task_cx| {
                let outcome = wait.as_mut().poll(task_cx);
                if outcome.is_ready() {
                    return outcome;
                }
                if cancel_at.as_mut().poll(task_cx).is_ready() {
                    cancellation.cancel();
                    task_cx.waker().wake_by_ref();
                }
                Poll::Pending
            })
            .await
            .unwrap()
        };
        assert_eq!(outcome, FinalTaskWaitOutcome::ObservationCancelled);
        assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
        let sentinel = client
            .get_task_final_with_cx(
                &cx,
                &McpRequestCancellation::new(),
                FinalTaskId::parse("sentinel").unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(sentinel.task, FinalTask::Cancelled(_)));
        client.close_with_cx(&cx).await.unwrap();
    });
}
