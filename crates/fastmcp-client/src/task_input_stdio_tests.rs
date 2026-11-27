//! Public Unix subprocess tests for explicit input submission and reconciliation.
//! The shell peer refuses duplicate updates and unrequested remote cancellation.

use super::*;
use crate::{ClientBuilder, ClientProtocolPlan, ProtocolPolicy, RequestTimeoutPolicy};
use fastmcp_core::McpErrorCode;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
            roots: Some(fastmcp_protocol::RootsCapability::default()),
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

const MRTR_DISCOVERY: &str = r#"
IFS= read -r discovery || exit 81
case "$discovery" in *'"method":"server/discover"'*) ;; *) exit 82 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"extensions":{"io.modelcontextprotocol/tasks":{}}},"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"mrtr-peer","version":"1"}}}}'
"#;

fn mrtr_call(id: u64) -> String {
    format!(
        r#"
IFS= read -r call || exit 101
case "$call" in *'"id":{id}'*) ;; *) exit 102 ;; esac
case "$call" in *'"method":"tools/call"'*) ;; *) exit 103 ;; esac
case "$call" in *'"name":"interactive"'*) ;; *) exit 104 ;; esac
case "$call" in *'"arguments":{{"text":"résumé 東京"}}'*) ;; *) exit 105 ;; esac
case "$call" in *'"io.modelcontextprotocol/tasks":{{}}'*) ;; *) exit 106 ;; esac
case "$call" in *'"io.modelcontextprotocol/protocolVersion":"2026-07-28"'*) ;; *) exit 107 ;; esac
case "$call" in *'"io.modelcontextprotocol/clientInfo":{{"name":"stdio-mrtr","version":"1"}}'*) ;; *) exit 108 ;; esac
"#
    )
}

fn mrtr_reply(id: u64, result: &Value) -> String {
    format!(
        "printf '%s\\n' '{}'\n",
        json!({"jsonrpc":"2.0","id":id,"result":result})
    )
}

fn mrtr_input() -> Value {
    json!({
        "resultType":"input_required", "requestState":"first-state",
        "inputRequests":{"roots":{"method":"roots/list"}}
    })
}

fn mrtr_terminal(create_task: bool) -> Value {
    let mut result = if create_task {
        json!({
            "resultType":"task", "taskId":"created-by-mrtr", "status":"working",
            "createdAt":"2026-07-28T00:00:00+00:00",
            "lastUpdatedAt":"2026-07-28T00:00:01Z", "ttlMs":null
        })
    } else {
        json!({"resultType":"complete", "content":[]})
    };
    result["_meta"] = json!({"com.example/receipt":"résumé 東京"});
    result["com.example/exact"] = Value::Number(
        serde_json::Number::from_string_unchecked("1.20e+4".to_owned()),
    );
    result
}

fn mrtr_answers(input: &crate::InputRequiredResult) -> crate::MrtrInputResponses {
    input
        .input_requests()
        .into_iter()
        .flat_map(|requests| requests.members())
        .map(|member| (member.name.clone(), json!({"roots":[]})))
        .collect()
}

fn mrtr_builder(roots: bool, handlers: crate::ReverseRequestHandlers) -> ClientBuilder {
    ClientBuilder::new()
        .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
        .client_info("stdio-mrtr", "1")
        .capabilities(fastmcp_protocol::ClientCapabilities {
            roots: roots.then(fastmcp_protocol::RootsCapability::default),
            ..fastmcp_protocol::ClientCapabilities::default()
        })
        .reverse_request_handlers(handlers)
        .request_timeout_policy(
            RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(2)).unwrap(),
        )
        .max_retries(0)
}

#[test]
fn public_stdio_tasks_mrtr_preserves_negotiation_and_exact_outcomes() {
    use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};

    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            for mode in ["installed", "sync", "async"] {
                for create_task in [false, true] {
                    let installed_calls = Arc::new(AtomicUsize::new(0));
                    let observed = Arc::clone(&installed_calls);
                    let handlers = crate::ReverseRequestHandlers::new().with_modern_roots_list(
                        move |caller, _, _| {
                            assert!(!caller.capabilities().spawn);
                            assert!(!Cx::current().unwrap().capabilities().spawn);
                            observed.fetch_add(1, Ordering::SeqCst);
                            Box::pin(async {
                                assert!(!Cx::current().unwrap().capabilities().spawn);
                                Ok(crate::FinalEmbeddedRootsListResult { roots: vec![] })
                            })
                        },
                    );
                    let script = format!(
                        "{MRTR_DISCOVERY}{}{}{}{}{}{}{}{}{}{}",
                        mrtr_call(2),
                        r#"
case "$call" in *'"requestState"'*|*'"inputResponses"'*) exit 109 ;; esac
case "$call" in *'"roots":{'*) ;; *) exit 110 ;; esac
"#,
                        mrtr_reply(2, &mrtr_input()),
                        mrtr_call(3),
                        r#"
case "$call" in *'"requestState":"first-state"'*) ;; *) exit 111 ;; esac
case "$call" in *'"inputResponses":{"roots":{"roots":[]}}'*) ;; *) exit 112 ;; esac
case "$call" in *'"roots":{'*) ;; *) exit 113 ;; esac
"#,
                        mrtr_reply(3, &json!({
                            "resultType":"input_required", "requestState":"second-state"
                        })),
                        mrtr_call(4),
                        r#"
case "$call" in *'"requestState":"second-state"'*) ;; *) exit 114 ;; esac
case "$call" in *'"inputResponses"'*) exit 115 ;; esac
case "$call" in *'"roots":{'*) ;; *) exit 116 ;; esac
"#,
                        mrtr_reply(4, &mrtr_terminal(create_task)),
                        sentinel(5),
                    );
                    let mut client = mrtr_builder(true, handlers)
                        .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
                        .await
                        .unwrap();
                    let caller = {
                        let _restricted =
                            Cx::push_restriction(CapSet::<false, true, true, true, true>::MASK);
                        Cx::current().unwrap()
                    };
                    let cancellation = McpRequestCancellation::new();
                    let local_calls = Arc::new(AtomicUsize::new(0));
                    let observed = Arc::clone(&local_calls);
                    let deadline = Instant::now() + Duration::from_secs(2);
                    let outcome = match mode {
                        "installed" => client
                            .call_tool_final_outcome_with_handlers_with_cx(
                                &caller,
                                &cancellation,
                                "interactive",
                                json!({"text":"résumé 東京"}),
                            )
                            .await,
                        "sync" => client
                            .call_tool_final_outcome_with_mrtr_retry_with_cx(
                                &caller,
                                &cancellation,
                                deadline,
                                "interactive",
                                json!({"text":"résumé 東京"}),
                                move |input| {
                                    assert!(!Cx::current().unwrap().capabilities().spawn);
                                    observed.fetch_add(1, Ordering::SeqCst);
                                    Ok(mrtr_answers(input))
                                },
                            )
                            .await,
                        _ => client
                            .call_tool_final_outcome_with_async_mrtr_retry_with_cx(
                                &caller,
                                &cancellation,
                                deadline,
                                "interactive",
                                json!({"text":"résumé 東京"}),
                                move |caller, input| {
                                    let observed = Arc::clone(&observed);
                                    Box::pin(async move {
                                        assert!(!caller.capabilities().spawn);
                                        assert!(!Cx::current().unwrap().capabilities().spawn);
                                        observed.fetch_add(1, Ordering::SeqCst);
                                        asupersync::runtime::yield_now().await;
                                        Ok(mrtr_answers(input))
                                    })
                                },
                            )
                            .await,
                    }
                    .unwrap();
                    let source = match outcome {
                        crate::FinalToolCallOutcome::Task(result) if create_task => {
                            assert_eq!(result.task.base().task_id.as_str(), "created-by-mrtr");
                            serde_json::to_string(&result).unwrap()
                        }
                        crate::FinalToolCallOutcome::Complete(result) if !create_task => {
                            crate::CoreResult::Final(crate::FinalCoreResult::ToolsCall {
                                result,
                                diagnostic: None,
                            })
                            .encode()
                            .unwrap()
                        }
                        result => panic!("unexpected final outcome: {result:?}"),
                    };
                    assert!(source.contains("1.20e+4"));
                    assert!(source.contains("résumé 東京"));
                    assert_eq!(
                        installed_calls.load(Ordering::SeqCst),
                        usize::from(mode == "installed")
                    );
                    assert_eq!(
                        local_calls.load(Ordering::SeqCst),
                        if mode == "installed" { 0 } else { 2 }
                    );
                    assert_eq!(
                        client.peek_next_request_id(),
                        5,
                        "no implicit Task poll or replay"
                    );
                    finish(&cx, &mut client).await;
                }
            }
        });
}

#[test]
fn public_stdio_tasks_mrtr_returns_unhandled_input_without_replay() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let input = mrtr_input();
            let script = format!(
                "{MRTR_DISCOVERY}{}{}{}",
                mrtr_call(2),
                mrtr_reply(2, &input),
                sentinel(3)
            );
            let mut client = mrtr_builder(true, crate::ReverseRequestHandlers::new())
                .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
                .await
                .unwrap();
            let outcome = client
                .call_tool_final_outcome_with_handlers_with_cx(
                    &cx,
                    &McpRequestCancellation::new(),
                    "interactive",
                    json!({"text":"résumé 東京"}),
                )
                .await
                .unwrap();
            let crate::FinalToolCallOutcome::InputRequired(result) = outcome else {
                panic!("unhandled input must remain input-required");
            };
            let source = crate::CoreResult::Final(crate::FinalCoreResult::ToolsCallInputRequired {
                result,
                diagnostic: None,
            })
            .encode()
            .unwrap();
            assert_eq!(serde_json::from_str::<Value>(&source).unwrap(), input);
            assert_eq!(client.peek_next_request_id(), 3);
            finish(&cx, &mut client).await;
        });
}

#[test]
fn public_stdio_tasks_mrtr_refuses_unadvertised_input_before_callbacks() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            for asynchronous in [false, true] {
                let script = format!(
                    "{MRTR_DISCOVERY}{}{}{}",
                    mrtr_call(2),
                    mrtr_reply(2, &mrtr_input()),
                    sentinel(3)
                );
                // Identical roots request to the positive test, but the caller
                // did not advertise roots and has installed no roots handler.
                let mut client = mrtr_builder(false, crate::ReverseRequestHandlers::new())
                    .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
                    .await
                    .unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&calls);
                let cancellation = McpRequestCancellation::new();
                let deadline = Instant::now() + Duration::from_secs(2);
                let error = if asynchronous {
                    client
                        .call_tool_final_outcome_with_async_mrtr_retry_with_cx(
                            &cx,
                            &cancellation,
                            deadline,
                            "interactive",
                            json!({"text":"résumé 東京"}),
                            move |_, input| {
                                observed.fetch_add(1, Ordering::SeqCst);
                                Box::pin(async move { Ok(mrtr_answers(input)) })
                            },
                        )
                        .await
                        .unwrap_err()
                } else {
                    client
                        .call_tool_final_outcome_with_mrtr_retry_with_cx(
                            &cx,
                            &cancellation,
                            deadline,
                            "interactive",
                            json!({"text":"résumé 東京"}),
                            move |input| {
                                observed.fetch_add(1, Ordering::SeqCst);
                                Ok(mrtr_answers(input))
                            },
                        )
                        .await
                        .unwrap_err()
                };
                assert_eq!(error.code, McpErrorCode::InvalidRequest);
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert_eq!(
                    client.peek_next_request_id(),
                    3,
                    "rejected input cannot spend a retry ID"
                );
                finish(&cx, &mut client).await;
            }
        });
}

#[test]
fn public_stdio_tasks_mrtr_rejects_inexact_or_failed_responses_without_replay() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            for mode in ["missing", "extra", "failed"] {
                let script = format!(
                    "{MRTR_DISCOVERY}{}{}{}",
                    mrtr_call(2),
                    mrtr_reply(2, &mrtr_input()),
                    sentinel(3)
                );
                let mut client = mrtr_builder(true, crate::ReverseRequestHandlers::new())
                    .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
                    .await
                    .unwrap();
                let mut calls = 0;
                let error = client
                    .call_tool_final_outcome_with_mrtr_retry_with_cx(
                        &cx,
                        &McpRequestCancellation::new(),
                        Instant::now() + Duration::from_secs(2),
                        "interactive",
                        json!({"text":"résumé 東京"}),
                        |input| {
                            calls += 1;
                            if mode == "failed" {
                                return Err(McpError::invalid_params("caller declined input"));
                            }
                            let mut responses = mrtr_answers(input);
                            if mode == "missing" {
                                responses.remove("roots");
                            } else {
                                responses.insert("unrequested".to_owned(), json!({"roots":[]}));
                            }
                            Ok(responses)
                        },
                    )
                    .await
                    .unwrap_err();
                assert_eq!(error.code, McpErrorCode::InvalidParams);
                assert_eq!(calls, 1);
                assert_eq!(client.peek_next_request_id(), 3);
                finish(&cx, &mut client).await;
            }
        });
}

#[test]
fn public_stdio_tasks_mrtr_failed_continuation_is_not_replayed() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let script = format!(
                "{MRTR_DISCOVERY}{}{}{}{}{}",
                mrtr_call(2),
                mrtr_reply(2, &mrtr_input()),
                mrtr_call(3),
                r#"
case "$call" in *'"requestState":"first-state"'*) ;; *) exit 111 ;; esac
case "$call" in *'"inputResponses":{"roots":{"roots":[]}}'*) ;; *) exit 112 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"continuation rejected"}}'
"#,
                sentinel(4)
            );
            let mut client = mrtr_builder(true, crate::ReverseRequestHandlers::new())
                .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
                .await
                .unwrap();
            let mut calls = 0;
            let error = client
                .call_tool_final_outcome_with_mrtr_retry_with_cx(
                    &cx,
                    &McpRequestCancellation::new(),
                    Instant::now() + Duration::from_secs(2),
                    "interactive",
                    json!({"text":"résumé 東京"}),
                    |input| {
                        calls += 1;
                        Ok(mrtr_answers(input))
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, McpErrorCode::InvalidParams);
            assert_eq!(error.message, "continuation rejected");
            assert_eq!(calls, 1);
            assert_eq!(client.peek_next_request_id(), 4);
            finish(&cx, &mut client).await;
        });
}

#[test]
fn public_stdio_tasks_mrtr_preflight_stops_before_deferred_discovery() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            for expired in [false, true] {
                let script = format!("{MRTR_DISCOVERY}{}", sentinel(2));
                let mut client = mrtr_builder(true, crate::ReverseRequestHandlers::new())
                    .auto_initialize(true)
                    .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
                    .await
                    .unwrap();
                let cancellation = McpRequestCancellation::new();
                let deadline = if expired {
                    Instant::now() - Duration::from_millis(1)
                } else {
                    cancellation.cancel();
                    Instant::now() + Duration::from_secs(2)
                };
                assert!(!client.is_initialized());
                let before_id = client.peek_next_request_id();
                let error = client
                    .call_tool_final_outcome_with_async_mrtr_retry_with_cx(
                        &cx,
                        &cancellation,
                        deadline,
                        "interactive",
                        json!({"text":"résumé 東京"}),
                        |_, _| panic!("a stopped operation cannot create a responder"),
                    )
                    .await
                    .unwrap_err();
                if expired {
                    assert_eq!(error.data.as_ref().unwrap()["timeoutSource"], "absolute");
                } else {
                    assert_eq!(error.code, McpErrorCode::RequestCancelled);
                }
                assert!(!client.is_initialized());
                assert_eq!(client.peek_next_request_id(), before_id);
                finish(&cx, &mut client).await;
            }
        });
}

#[test]
fn public_stdio_tasks_mrtr_pending_responder_is_owned_by_cancellation_and_drop() {
    use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};

    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            assert!(!Cx::current().unwrap().capabilities().spawn);
            self.0.store(true, Ordering::SeqCst);
        }
    }

    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            for stop in ["cancel", "drop", "deadline"] {
                let script = format!(
                    "{MRTR_DISCOVERY}{}{}{}",
                    mrtr_call(2),
                    mrtr_reply(2, &mrtr_input()),
                    sentinel(3)
                );
                let mut client = mrtr_builder(true, crate::ReverseRequestHandlers::new())
                    .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
                    .await
                    .unwrap();
                let caller = {
                    let _restricted =
                        Cx::push_restriction(CapSet::<false, true, true, true, true>::MASK);
                    Cx::current().unwrap()
                };
                let entered = Arc::new(AtomicBool::new(false));
                let dropped = Arc::new(AtomicBool::new(false));
                let callback_entered = Arc::clone(&entered);
                let callback_dropped = Arc::clone(&dropped);
                let cancellation = McpRequestCancellation::new();
                let deadline = Instant::now() + Duration::from_secs(2);
                let mut operation = Box::pin(
                    client.call_tool_final_outcome_with_async_mrtr_retry_with_cx(
                        &caller,
                        &cancellation,
                        deadline,
                        "interactive",
                        json!({"text":"résumé 東京"}),
                        move |caller, input| {
                            let entered = Arc::clone(&callback_entered);
                            let dropped = Arc::clone(&callback_dropped);
                            Box::pin(async move {
                                assert!(!caller.capabilities().spawn);
                                assert!(!Cx::current().unwrap().capabilities().spawn);
                                assert_eq!(input.input_requests().unwrap().members().len(), 1);
                                let _dropped = Dropped(dropped);
                                entered.store(true, Ordering::SeqCst);
                                std::future::pending::<McpResult<crate::MrtrInputResponses>>().await
                            })
                        },
                    ),
                );
                while !entered.load(Ordering::SeqCst) {
                    std::future::poll_fn(|task| {
                        assert!(operation.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    asupersync::runtime::yield_now().await;
                }
                assert!(!dropped.load(Ordering::SeqCst));
                if stop != "drop" {
                    if stop == "cancel" {
                        cancellation.cancel();
                    } else {
                        asupersync::time::sleep(
                            cx.now(),
                            deadline.saturating_duration_since(Instant::now())
                                + Duration::from_millis(1),
                        )
                        .await;
                    }
                    let error = operation.as_mut().await.unwrap_err();
                    if stop == "cancel" {
                        assert_eq!(error.code, McpErrorCode::RequestCancelled);
                    } else {
                        assert_eq!(error.data.as_ref().unwrap()["timeoutSource"], "absolute");
                    }
                }
                drop(operation);
                assert!(
                    dropped.load(Ordering::SeqCst),
                    "the callback cannot outlive its operation"
                );
                assert_eq!(cancellation.is_cancel_requested(), stop == "cancel");
                assert!(caller.checkpoint().is_ok());
                assert_eq!(client.peek_next_request_id(), 3);
                finish(&cx, &mut client).await;
            }
        });
}

#[test]
fn public_stdio_tasks_mrtr_synchronous_responder_cancellation_cannot_send_answers() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let script = format!(
                "{MRTR_DISCOVERY}{}{}{}",
                mrtr_call(2),
                mrtr_reply(2, &mrtr_input()),
                sentinel(3)
            );
            let mut client = mrtr_builder(true, crate::ReverseRequestHandlers::new())
                .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
                .await
                .unwrap();
            let cancellation = McpRequestCancellation::new();
            let mut calls = 0;
            let error = client
                .call_tool_final_outcome_with_mrtr_retry_with_cx(
                    &cx,
                    &cancellation,
                    Instant::now() + Duration::from_secs(2),
                    "interactive",
                    json!({"text":"résumé 東京"}),
                    |input| {
                        calls += 1;
                        cancellation.cancel();
                        Ok(mrtr_answers(input))
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, McpErrorCode::RequestCancelled);
            assert_eq!(calls, 1);
            assert_eq!(client.peek_next_request_id(), 3);
            finish(&cx, &mut client).await;
        });
}

#[test]
fn public_stdio_tasks_mrtr_requires_discovery_admission_before_tool_commit() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let discovery = MRTR_DISCOVERY.replace(
                r#""extensions":{"io.modelcontextprotocol/tasks":{}}"#,
                r#""extensions":{}"#,
            );
            assert_ne!(discovery, MRTR_DISCOVERY);
            let script = format!(
                "{discovery}{}",
                r#"
IFS= read -r probe || exit 101
case "$probe" in *'"id":2'*) ;; *) exit 102 ;; esac
case "$probe" in *'"method":"server/discover"'*) ;; *) exit 103 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{}}'
exec sleep 10
"#
            );
            let mut client = mrtr_builder(true, crate::ReverseRequestHandlers::new())
                .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
                .await
                .unwrap();
            let cancellation = McpRequestCancellation::new();
            let mut calls = 0;
            let error = client
                .call_tool_final_outcome_with_mrtr_retry_with_cx(
                    &cx,
                    &cancellation,
                    Instant::now() + Duration::from_secs(2),
                    "interactive",
                    json!({"text":"résumé 東京"}),
                    |input| {
                        calls += 1;
                        Ok(mrtr_answers(input))
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, McpErrorCode::InvalidParams);
            assert_eq!(calls, 0);
            assert_eq!(client.peek_next_request_id(), 2);
            client.ping_with_cx(&cx, &cancellation).await.unwrap();
            client.close_with_cx(&cx).await.unwrap();
            assert!(cx.checkpoint().is_ok());
        });
}

#[test]
fn public_stdio_tasks_mrtr_only_admitted_task_receipts_survive_a_late_stop() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            for stop in ["cancel", "deadline"] {
                for branch in ["task", "complete", "input"] {
                    let result = if branch == "input" {
                        json!({
                            "resultType":"input_required", "requestState":"second-state",
                            "inputRequests":{"roots":{"method":"roots/list"}}
                        })
                    } else {
                        mrtr_terminal(branch == "task")
                    };
                    let script = format!(
                        "{MRTR_DISCOVERY}{}{}{}{}{}",
                        mrtr_call(2),
                        mrtr_reply(2, &mrtr_input()),
                        mrtr_call(3),
                        mrtr_reply(3, &result),
                        sentinel(4)
                    );
                    let mut client = mrtr_builder(true, crate::ReverseRequestHandlers::new())
                        .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
                        .await
                        .unwrap();
                    let executor = client.multiplexed_stdio_executor().unwrap();
                    let next_id = Arc::clone(&client.next_id);
                    let cancellation = McpRequestCancellation::new();
                    let calls = Arc::new(AtomicUsize::new(0));
                    let observed = Arc::clone(&calls);
                    let deadline = Instant::now() + Duration::from_secs(2);
                    let mut operation = Box::pin(
                        client.call_tool_final_outcome_with_mrtr_retry_with_cx(
                            &cx,
                            &cancellation,
                            deadline,
                            "interactive",
                            json!({"text":"résumé 東京"}),
                            move |input| {
                                observed.fetch_add(1, Ordering::SeqCst);
                                Ok(mrtr_answers(input))
                            },
                        ),
                    );
                    loop {
                        let pending = std::future::poll_fn(|task| {
                            Poll::Ready(operation.as_mut().poll(task))
                        })
                        .await;
                        assert!(
                            pending.is_pending(),
                            "the receive slice yields before its owner consumes the result"
                        );
                        if next_id.load(Ordering::SeqCst) == 4
                            && !executor.executor.pending_records().iter().any(|record| {
                                record.request_id == RequestId::Number(3)
                            })
                        {
                            break;
                        }
                        asupersync::runtime::yield_now().await;
                    }
                    // The sole ingress owner has admitted this exact terminal
                    // frame, but the convenience future has not consumed it.
                    if stop == "cancel" {
                        cancellation.cancel();
                    } else {
                        asupersync::time::sleep(
                            cx.now(),
                            deadline.saturating_duration_since(Instant::now())
                                + Duration::from_millis(1),
                        )
                        .await;
                    }
                    let outcome = operation.await;
                    if branch == "task" {
                        let crate::FinalToolCallOutcome::Task(receipt) = outcome.unwrap() else {
                            panic!("an admitted durable Task must remain addressable");
                        };
                        assert_eq!(serde_json::to_value(&receipt).unwrap(), result);
                        assert!(
                            serde_json::to_string(&receipt)
                                .unwrap()
                                .contains("1.20e+4")
                        );
                    } else {
                        let error = outcome.unwrap_err();
                        if stop == "cancel" {
                            assert_eq!(error.code, McpErrorCode::RequestCancelled);
                        } else {
                            assert_eq!(
                                error.data.as_ref().unwrap()["timeoutSource"],
                                "absolute"
                            );
                        }
                    }
                    assert_eq!(
                        calls.load(Ordering::SeqCst),
                        1,
                        "a stopped input round cannot invoke the responder"
                    );
                    assert_eq!(
                        client.peek_next_request_id(),
                        4,
                        "no implicit Task poll, cancel, or retry"
                    );
                    finish(&cx, &mut client).await;
                }
            }
        });
}

#[test]
fn public_stdio_tasks_mrtr_pending_continuation_preserves_cleanup_failures() {
    use fastmcp_transport::TransportSendHalf;

    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            for mode in ["cancel", "drop", "closed-writer"] {
                // The peer consumes the continuation but withholds its result.
                // Any replay or remote tasks/cancel is rejected by the sentinel.
                let script = format!(
                    "{MRTR_DISCOVERY}{}{}{}{}",
                    mrtr_call(2),
                    mrtr_reply(2, &mrtr_input()),
                    mrtr_call(3),
                    sentinel(4)
                );
                let mut client = mrtr_builder(true, crate::ReverseRequestHandlers::new())
                    .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
                    .await
                    .unwrap();
                let next_id = Arc::clone(&client.next_id);
                let sender = Arc::clone(&client.response_sender);
                let cancellation = McpRequestCancellation::new();
                let mut operation = Box::pin(
                    client.call_tool_final_outcome_with_mrtr_retry_with_cx(
                        &cx,
                        &cancellation,
                        Instant::now() + Duration::from_secs(2),
                        "interactive",
                        json!({"text":"résumé 東京"}),
                        |input| Ok(mrtr_answers(input)),
                    ),
                );
                loop {
                    std::future::poll_fn(|task| {
                        assert!(operation.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    if next_id.load(Ordering::SeqCst) == 4 {
                        break;
                    }
                    asupersync::runtime::yield_now().await;
                }
                if mode == "closed-writer" {
                    crate::SharedStdioSend(sender).close(&cx).unwrap();
                }
                let error = if mode == "drop" {
                    None
                } else {
                    cancellation.cancel();
                    Some(operation.as_mut().await.unwrap_err())
                };
                drop(operation);
                assert_eq!(client.peek_next_request_id(), 4);
                if mode == "closed-writer" {
                    let error = error.unwrap();
                    assert_eq!(error.code, McpErrorCode::InternalError);
                    assert!(error.message.contains("closed"));
                    assert!(client.transport_is_closed());
                    let terminal = client.responses.terminal_error().unwrap();
                    assert_eq!(error.code, terminal.code);
                    assert_eq!(error.message, terminal.message);
                    let repeated = client
                        .call_tool_final_outcome_with_handlers_with_cx(
                            &cx,
                            &McpRequestCancellation::new(),
                            "interactive",
                            json!({"text":"résumé 東京"}),
                        )
                        .await
                        .unwrap_err();
                    assert_eq!(repeated.message, error.message);
                    assert_eq!(
                        client.peek_next_request_id(),
                        4,
                        "a terminal writer cannot restart the operation"
                    );
                    client.close_with_cx(&cx).await.unwrap();
                } else {
                    if let Some(error) = error {
                        assert_eq!(error.code, McpErrorCode::RequestCancelled);
                    }
                    finish(&cx, &mut client).await;
                }
                assert!(cx.checkpoint().is_ok());
            }
        });
}

#[test]
fn stdio_tasks_mrtr_precommit_deadline_does_not_allocate_or_write() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let script = format!("{MRTR_DISCOVERY}{}", sentinel(2));
            let mut client = mrtr_builder(true, crate::ReverseRequestHandlers::new())
                .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
                .await
                .unwrap();
            let cancellation = McpRequestCancellation::new();
            let before_id = client.peek_next_request_id();
            // Exercise the shared commit boundary directly: the public
            // operation's earlier stop check cannot cover time consumed by
            // servicing a predecessor's connection-owned cleanup.
            let error = client
                .start_prepared_yielding_final_request(
                    &cx,
                    Some(&cancellation),
                    "tools/call",
                    json!({"name":"interactive", "arguments":{"text":"résumé 東京"}}),
                    true,
                    Some(Instant::now() - Duration::from_millis(1)),
                )
                .unwrap_err();
            assert_eq!(error.data.as_ref().unwrap()["timeoutSource"], "absolute");
            assert_eq!(client.peek_next_request_id(), before_id);
            assert!(client.is_initialized());
            finish(&cx, &mut client).await;
        });
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
