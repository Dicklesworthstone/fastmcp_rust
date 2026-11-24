//! Native subprocess coverage for caller-owned, cooperative MRTR responders.

use std::collections::HashMap;
use std::future::poll_fn;
use std::pin::pin;
use std::task::Poll;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use asupersync::runtime::RuntimeBuilder;
use serde_json::{Value, json};

use super::*;

fn run<F: Future<Output = ()>>(test: impl FnOnce(Cx) -> F) {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(30), test(cx))
            .await
            .expect("stdio MRTR must make progress on its caller's runtime");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn builder() -> ClientBuilder {
    let capabilities = json!({
        "roots": {},
        "extensions": {"com.example/preserved": {"mode": "read"}},
    });
    #[cfg(feature = "tasks")]
    let capabilities = {
        let mut capabilities = capabilities;
        capabilities["extensions"]["io.modelcontextprotocol/tasks"] = json!({});
        capabilities
    };
    ClientBuilder::new()
        .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
        .client_info("stdio-explicit-mrtr", "1")
        .capabilities(serde_json::from_value(capabilities).unwrap())
        .request_timeout_policy(
            RequestTimeoutPolicy::new(Duration::from_secs(5), Duration::from_secs(10)).unwrap(),
        )
        .max_retries(0)
}

fn response(id: usize, result: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
}

fn discovery() -> String {
    response(
        1,
        json!({
            "resultType": "complete", "supportedVersions": ["2026-07-28"],
            "capabilities": {"extensions": {"io.modelcontextprotocol/tasks": {}}},
            "ttlMs": 0, "cacheScope": "private",
        }),
    )
}

fn roots_input(count: usize, state: &str) -> Value {
    let requests: serde_json::Map<String, Value> = (0..count)
        .map(|index| (format!("root-{index}"), json!({"method": "roots/list"})))
        .collect();
    json!({
        "resultType": "input_required", "requestState": state,
        "inputRequests": requests,
    })
}

#[allow(clippy::unnecessary_wraps)]
fn answer_roots(input: &InputRequiredResult) -> McpResult<MrtrInputResponses> {
    Ok(input
        .input_requests()
        .into_iter()
        .flat_map(|requests| requests.members())
        .map(|member| (member.name.clone(), json!({"roots": []})))
        .collect())
}

async fn connected(cx: &Cx, builder: ClientBuilder, script: &str, args: &[String]) -> Client {
    let mut command_args = vec!["-c", script, "stdio-mrtr-test"];
    command_args.extend(args.iter().map(String::as_str));
    builder
        .connect_stdio_with_cx(cx, "sh", &command_args)
        .await
        .expect("the public native stdio builder connects")
}

async fn assert_reusable(cx: &Cx, client: &mut Client, expected_id: u64) {
    assert_eq!(client.next_id.load(Ordering::SeqCst), expected_id);
    let result = client
        .request_core_with_cx(cx, &McpRequestCancellation::new(), "tools/list", json!({}))
        .await
        .expect("refusing an MRTR continuation must preserve the connection");
    assert!(matches!(
        result,
        CoreResult::Final(FinalCoreResult::ToolsList { .. })
    ));
    cx.checkpoint().unwrap();
    client.close_with_cx(cx).await.unwrap();
    assert!(client.child.is_none());
}

fn tools(id: usize) -> String {
    response(
        id,
        json!({"resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private"}),
    )
}

#[derive(Clone, Copy, Debug)]
enum Verb {
    Tool,
    Resource,
    Prompt,
}

impl Verb {
    fn method(self) -> &'static str {
        match self {
            Self::Tool => "tools/call",
            Self::Resource => "resources/read",
            Self::Prompt => "prompts/get",
        }
    }

    fn original(self) -> Value {
        match self {
            Self::Tool | Self::Prompt => {
                json!({"name": "interactive", "arguments": {"value": "résumé 東京"}})
            }
            Self::Resource => json!({"uri": "file:///interactive"}),
        }
    }

    fn completed_fields(self) -> &'static str {
        match self {
            Self::Tool => r#""resultType":"complete","content":[],"isError":false"#,
            Self::Resource => {
                r#""resultType":"complete","contents":[],"ttlMs":60000,"cacheScope":"private""#
            }
            Self::Prompt => r#""resultType":"complete","messages":[]"#,
        }
    }

    async fn call<F>(
        self,
        client: &mut Client,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
        respond: F,
    ) -> McpResult<CoreResult>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
    {
        match self {
            Self::Tool => {
                client
                    .call_tool_with_mrtr_retry_with_cx(
                        cx,
                        cancellation,
                        deadline,
                        "interactive",
                        json!({"value": "résumé 東京"}),
                        respond,
                    )
                    .await
            }
            Self::Resource => {
                client
                    .read_resource_with_mrtr_retry_with_cx(
                        cx,
                        cancellation,
                        deadline,
                        "file:///interactive",
                        respond,
                    )
                    .await
            }
            Self::Prompt => {
                client
                    .get_prompt_with_mrtr_retry_with_cx(
                        cx,
                        cancellation,
                        deadline,
                        "interactive",
                        HashMap::from([("value".to_owned(), "résumé 東京".to_owned())]),
                        respond,
                    )
                    .await
            }
        }
    }

    async fn call_async<F>(
        self,
        client: &mut Client,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
        respond: F,
    ) -> McpResult<CoreResult>
    where
        F: for<'a> FnMut(&'a Cx, &'a InputRequiredResult) -> MrtrResponderFuture<'a>,
    {
        match self {
            Self::Tool => {
                client
                    .call_tool_with_async_mrtr_retry_with_cx(
                        cx,
                        cancellation,
                        deadline,
                        "interactive",
                        json!({"value": "résumé 東京"}),
                        respond,
                    )
                    .await
            }
            Self::Resource => {
                client
                    .read_resource_with_async_mrtr_retry_with_cx(
                        cx,
                        cancellation,
                        deadline,
                        "file:///interactive",
                        respond,
                    )
                    .await
            }
            Self::Prompt => {
                client
                    .get_prompt_with_async_mrtr_retry_with_cx(
                        cx,
                        cancellation,
                        deadline,
                        "interactive",
                        HashMap::from([("value".to_owned(), "résumé 東京".to_owned())]),
                        respond,
                    )
                    .await
            }
        }
    }

    fn completed_source(self, result: CoreResult) -> String {
        fn encode<T>(result: &fastmcp_protocol::CompleteResult<T>) -> String {
            fastmcp_protocol::encode_complete_result(&result.meta, Vec::new(), &[], &result.extras)
                .unwrap()
        }
        match (self, result) {
            (Self::Tool, CoreResult::Final(FinalCoreResult::ToolsCall { result, .. })) => {
                encode(&result)
            }
            (Self::Resource, CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. })) => {
                encode(&result)
            }
            (Self::Prompt, CoreResult::Final(FinalCoreResult::PromptsGet { result, .. })) => {
                encode(&result)
            }
            _ => panic!("MRTR must preserve its exact method result family"),
        }
    }
}

const MULTI_ROUND: &str = r#"
IFS= read -r discover || exit 80
printf '%s\n' "$1"
IFS= read -r original || exit 81
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"resultType":"input_required","requestState":"first","inputRequests":{"first":{"method":"roots/list"}}}}'
IFS= read -r first || exit 82
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"resultType":"input_required","inputRequests":{"second":{"method":"roots/list"}}}}'
IFS= read -r second || exit 83
printf '%s\n' '{"jsonrpc":"2.0","id":4,"result":{"resultType":"input_required","requestState":"third"}}'
IFS= read -r third || exit 84
printf '{"jsonrpc":"2.0","id":5,"result":{%s,"com.example/requests":[%s,%s,%s,%s],"com.example/exact":7.30e-2,"com.example/receipt":"résumé 東京"}}\n' "$2" "$original" "$first" "$second" "$third"
IFS= read -r unexpected && exit 85
exit 0
"#;

#[test]
fn stdio_explicit_mrtr_all_verbs_preserve_rounds_metadata_and_exact_results() {
    fn assert_send<T: Send>(future: T) -> T {
        future
    }

    run(|cx| async move {
        for verb in [Verb::Tool, Verb::Resource, Verb::Prompt] {
            for installed in [false, true] {
                let installed_calls = Arc::new(AtomicUsize::new(0));
                let builder = if installed {
                    let calls = Arc::clone(&installed_calls);
                    builder().reverse_request_handlers(
                        ReverseRequestHandlers::new().with_modern_roots_list(move |_, _, _| {
                            calls.fetch_add(1, Ordering::SeqCst);
                            Box::pin(async {
                                Ok(FinalEmbeddedRootsListResult { roots: Vec::new() })
                            })
                        }),
                    )
                } else {
                    builder()
                };
                let mut client = connected(
                    &cx,
                    builder.auto_initialize(true),
                    MULTI_ROUND,
                    &[discovery(), verb.completed_fields().to_owned()],
                )
                .await;
                assert!(!client.is_initialized());
                let cancellation = McpRequestCancellation::new();
                // The installed-handler wrapper also remains Send after sharing
                // its driver with the per-operation callback path.
                drop(assert_send(client.call_tool_with_cx(
                    &cx,
                    &cancellation,
                    "unpolled",
                    json!({}),
                )));
                let mut states = Vec::new();
                let result = assert_send(verb.call(
                    &mut client,
                    &cx,
                    &cancellation,
                    Instant::now() + Duration::from_secs(10),
                    |input| {
                        states.push(input.request_state().map(str::to_owned));
                        answer_roots(input)
                    },
                ))
                .await
                .unwrap();
                assert_eq!(
                    states,
                    [Some("first".to_owned()), None, Some("third".to_owned())]
                );
                assert_eq!(installed_calls.load(Ordering::SeqCst), 0);
                let source = verb.completed_source(result);
                assert!(source.contains("7.30e-2"));
                let result: Value = serde_json::from_str(&source).unwrap();
                assert_eq!(result["com.example/receipt"], "résumé 東京");
                let requests = result["com.example/requests"].as_array().unwrap();
                assert_eq!(requests.len(), 4);
                let original = &requests[0]["params"];
                for (key, value) in verb.original().as_object().unwrap() {
                    assert_eq!(&original[key], value);
                }
                assert_eq!(
                    original["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"]["com.example/preserved"]
                        ["mode"],
                    "read"
                );
                assert!(
                    original["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"]
                        .get("io.modelcontextprotocol/tasks")
                        .is_none()
                );
                for (round, request) in requests.iter().enumerate() {
                    assert_eq!(request["id"], round + 2);
                    assert_eq!(request["method"], verb.method());
                    let mut parameters = request["params"].clone();
                    if round > 0 {
                        let expected_state = match round {
                            1 => Some(json!("first")),
                            2 => None,
                            3 => Some(json!("third")),
                            _ => unreachable!(),
                        };
                        let expected_responses = match round {
                            1 => Some(json!({"first": {"roots": []}})),
                            2 => Some(json!({"second": {"roots": []}})),
                            3 => None,
                            _ => unreachable!(),
                        };
                        assert_eq!(parameters.get("requestState"), expected_state.as_ref());
                        assert_eq!(
                            parameters.get("inputResponses"),
                            expected_responses.as_ref()
                        );
                        parameters.as_object_mut().unwrap().remove("requestState");
                        parameters.as_object_mut().unwrap().remove("inputResponses");
                    }
                    assert_eq!(&parameters, original);
                }
                assert_eq!(client.next_id.load(Ordering::SeqCst), 6);
                assert_eq!(client.final_result_cache_stats().fills, 0);
                client.close_with_cx(&cx).await.unwrap();
                assert!(client.child.is_none());
            }
        }
    });
}

// The only accepted frame after the challenge is an independent tools/list.
// An accidental continuation therefore fails visibly instead of merely being
// inferred from a local callback counter or request allocator.
const REJECT_CONTINUATION: &str = r#"
IFS= read -r discover || exit 80
printf '%s\n' "$1"
IFS= read -r original || exit 81
printf '%s\n' "$2"
IFS= read -r reuse || exit 82
case "$reuse" in *'"method":"tools/list"'*) ;; *) exit 83;; esac
printf '%s\n' "$3"
IFS= read -r unexpected && exit 84
exit 0
"#;

#[test]
fn stdio_explicit_mrtr_admits_entire_capability_batch_before_callback() {
    run(|cx| async move {
        let challenge = json!({
            "resultType": "input_required", "requestState": "unadmitted",
            "inputRequests": {
                "first": {"method": "roots/list"},
                "second": {"method": "elicitation/create", "params": {
                    "mode": "form", "message": "Approve", "requestedSchema": {
                        "type": "object", "properties": {},
                    },
                }},
            },
        });
        for verb in [Verb::Tool, Verb::Resource, Verb::Prompt] {
            let mut client = connected(
                &cx,
                builder(),
                REJECT_CONTINUATION,
                &[discovery(), response(2, challenge.clone()), tools(3)],
            )
            .await;
            let mut calls = 0;
            let error = verb
                .call(
                    &mut client,
                    &cx,
                    &McpRequestCancellation::new(),
                    Instant::now() + Duration::from_secs(5),
                    |input| {
                        calls += 1;
                        answer_roots(input)
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, McpErrorCode::InvalidRequest);
            assert!(error.message.contains("unadvertised client capability"));
            assert_eq!(calls, 0);
            assert_reusable(&cx, &mut client, 3).await;
        }
    });
}

#[test]
fn stdio_explicit_mrtr_rejects_failed_cancelled_incomplete_and_late_callbacks() {
    run(|cx| async move {
        for case in ["error", "cancel", "missing", "foreign", "late"] {
            let mut client = connected(
                &cx,
                builder(),
                REJECT_CONTINUATION,
                &[
                    discovery(),
                    response(2, roots_input(1, "callback")),
                    tools(3),
                ],
            )
            .await;
            let cancellation = McpRequestCancellation::new();
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut calls = 0;
            let error = Verb::Tool
                .call(&mut client, &cx, &cancellation, deadline, |input| {
                    calls += 1;
                    match case {
                        "error" => Err(McpError::invalid_request("host declined input")),
                        "cancel" => {
                            cancellation.cancel();
                            answer_roots(input)
                        }
                        "missing" => Ok(MrtrInputResponses::new()),
                        "foreign" => Ok(MrtrInputResponses::from([(
                            "foreign".to_owned(),
                            json!({"roots": []}),
                        )])),
                        "late" => {
                            // A synchronous user callback cannot be preempted.
                            // Its late answer still must not authorize a send.
                            std::thread::sleep(
                                deadline.saturating_duration_since(Instant::now())
                                    + Duration::from_millis(1),
                            );
                            answer_roots(input)
                        }
                        _ => unreachable!(),
                    }
                })
                .await
                .unwrap_err();
            assert_eq!(calls, 1, "{case}");
            assert_eq!(
                error.code,
                match case {
                    "error" => McpErrorCode::InvalidRequest,
                    "cancel" => McpErrorCode::RequestCancelled,
                    "missing" | "foreign" => McpErrorCode::InvalidParams,
                    "late" => McpErrorCode::InternalError,
                    _ => unreachable!(),
                },
                "{case}: {error:?}"
            );
            if case == "late" {
                assert_eq!(error.data.as_ref().unwrap()["timeoutSource"], "absolute");
            }
            assert_reusable(&cx, &mut client, 3).await;
        }
    });
}

#[test]
fn stdio_explicit_mrtr_yields_for_inflight_cancellation_and_reuses_connection() {
    const SCRIPT: &str = r#"
IFS= read -r discover || exit 80
printf '%s\n' "$1"
IFS= read -r original || exit 81
case "$original" in *'"method":"tools/call"'*) ;; *) exit 82;; esac
IFS= read -r cancelled || exit 83
case "$cancelled" in *'"method":"notifications/cancelled"'*'"requestId":2'*) ;; *) exit 84;; esac
IFS= read -r reuse || exit 85
case "$reuse" in *'"method":"tools/list"'*) ;; *) exit 86;; esac
printf '%s\n' "$2"
IFS= read -r unexpected && exit 87
exit 0
"#;
    run(|cx| async move {
        let mut client = connected(&cx, builder(), SCRIPT, &[discovery(), tools(3)]).await;
        let cancellation = McpRequestCancellation::new();
        let cancel = cancellation.clone();
        let next_id = Arc::clone(&client.next_id);
        let mut cancelling = cx
            .spawn(move |_| async move {
                // Publication is synchronous. On this one-thread runtime the
                // sibling can observe ID consumption only after the request
                // has committed and the public operation has yielded.
                while next_id.load(Ordering::SeqCst) == 2 {
                    asupersync::runtime::yield_now().await;
                }
                cancel.cancel();
            })
            .unwrap();
        let mut calls = 0;
        let error = Verb::Tool
            .call(
                &mut client,
                &cx,
                &cancellation,
                Instant::now() + Duration::from_secs(5),
                |input| {
                    calls += 1;
                    answer_roots(input)
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert_eq!(calls, 0);
        cancelling.join(&cx).await.unwrap();
        assert_reusable(&cx, &mut client, 3).await;
    });
}

#[test]
fn stdio_explicit_mrtr_refuses_stopped_owners_before_initialization_or_dispatch() {
    const SCRIPT: &str = r#"
IFS= read -r discover || exit 80
case "$discover" in *'"method":"server/discover"'*) ;; *) exit 81;; esac
printf '%s\n' "$1"
IFS= read -r reuse || exit 82
case "$reuse" in *'"method":"tools/list"'*) ;; *) exit 83;; esac
printf '%s\n' "$2"
IFS= read -r unexpected && exit 84
exit 0
"#;
    run(|cx| async move {
        for cancelled in [false, true] {
            let mut client = connected(
                &cx,
                builder().auto_initialize(true),
                SCRIPT,
                &[discovery(), tools(2)],
            )
            .await;
            let next_id = client.next_id.load(Ordering::SeqCst);
            let cancellation = McpRequestCancellation::new();
            if cancelled {
                cancellation.cancel();
            }
            let deadline = if cancelled {
                Instant::now() + Duration::from_secs(5)
            } else {
                Instant::now()
            };
            let mut calls = 0;
            let error = Verb::Tool
                .call(&mut client, &cx, &cancellation, deadline, |input| {
                    calls += 1;
                    answer_roots(input)
                })
                .await
                .unwrap_err();
            assert_eq!(calls, 0);
            assert_eq!(client.next_id.load(Ordering::SeqCst), next_id);
            assert!(!client.is_initialized());
            assert_eq!(
                error.code,
                if cancelled {
                    McpErrorCode::RequestCancelled
                } else {
                    McpErrorCode::InternalError
                }
            );
            // A fresh operation performs discovery itself. The peer will fail
            // if the refused call sent either discovery or an application RPC.
            let result = client
                .request_core_with_cx(&cx, &McpRequestCancellation::new(), "tools/list", json!({}))
                .await
                .unwrap();
            assert!(matches!(
                result,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            assert_eq!(client.next_id.load(Ordering::SeqCst), 3);
            client.close_with_cx(&cx).await.unwrap();
            assert!(client.child.is_none());
        }
    });
}

#[test]
fn stdio_explicit_mrtr_enforces_round_and_total_response_bounds_before_callback() {
    const SCRIPT: &str = r#"
IFS= read -r discover || exit 80
printf '%s\n' "$1"
shift
while [ "$#" -gt 1 ]; do
    IFS= read -r request || exit 81
    case "$request" in *'"method":"tools/call"'*) ;; *) exit 82;; esac
    printf '%s\n' "$1"
    shift
done
IFS= read -r reuse || exit 83
case "$reuse" in *'"method":"tools/list"'*) ;; *) exit 84;; esac
printf '%s\n' "$1"
IFS= read -r unexpected && exit 85
exit 0
"#;
    run(|cx| async move {
        let rounds = vec![json!({"resultType": "input_required", "requestState": "again"}); 5];
        let responses = vec![roots_input(65, "first"), roots_input(64, "second")];
        for (challenges, expected_callbacks) in [(rounds, 4), (responses, 1)] {
            let next_id = challenges.len() + 2;
            let mut args = vec![discovery()];
            args.extend(
                challenges
                    .into_iter()
                    .enumerate()
                    .map(|(index, challenge)| response(index + 2, challenge)),
            );
            args.push(tools(next_id));
            let mut client = connected(&cx, builder(), SCRIPT, &args).await;
            let mut calls = 0;
            let error = Verb::Tool
                .call(
                    &mut client,
                    &cx,
                    &McpRequestCancellation::new(),
                    Instant::now() + Duration::from_secs(5),
                    |input| {
                        calls += 1;
                        answer_roots(input)
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(calls, expected_callbacks);
            assert_eq!(error.code, McpErrorCode::InvalidParams);
            assert_reusable(&cx, &mut client, u64::try_from(next_id).unwrap()).await;
        }
    });
}

#[test]
fn stdio_async_mrtr_all_verbs_borrow_caller_and_preserve_rounds() {
    fn assert_send<T: Send>(future: T) -> T {
        future
    }

    run(|cx| async move {
        for verb in [Verb::Tool, Verb::Resource, Verb::Prompt] {
            let installed_calls = Arc::new(AtomicUsize::new(0));
            let observed_installed = Arc::clone(&installed_calls);
            let handlers = ReverseRequestHandlers::new().with_modern_roots_list(
                move |_, _, _| {
                    observed_installed.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async {
                        Ok(FinalEmbeddedRootsListResult { roots: Vec::new() })
                    })
                },
            );
            let mut client = connected(
                &cx,
                builder().reverse_request_handlers(handlers).auto_initialize(true),
                MULTI_ROUND,
                &[discovery(), verb.completed_fields().to_owned()],
            )
            .await;
            assert!(!client.is_initialized());
            let cancellation = McpRequestCancellation::new();
            let pending_polls = Arc::new(AtomicUsize::new(0));
            let states = Arc::new(Mutex::new(Vec::new()));
            let observed_pending = Arc::clone(&pending_polls);
            let observed_states = Arc::clone(&states);
            let expected_task = cx.task_id();
            let expected_region = cx.region_id();
            let result = assert_send(verb.call_async(
                &mut client,
                &cx,
                &cancellation,
                Instant::now() + Duration::from_secs(10),
                move |caller, input| {
                    let pending = Arc::clone(&observed_pending);
                    let states = Arc::clone(&observed_states);
                    Box::pin(async move {
                        assert_eq!(caller.task_id(), expected_task);
                        assert_eq!(caller.region_id(), expected_region);
                        assert!(caller.blocking_pool_handle().is_none());
                        let mut yielded = false;
                        poll_fn(|task| {
                            assert_eq!(Cx::current().unwrap().task_id(), expected_task);
                            if yielded {
                                Poll::Ready(())
                            } else {
                                yielded = true;
                                pending.fetch_add(1, Ordering::SeqCst);
                                task.waker().wake_by_ref();
                                Poll::Pending
                            }
                        })
                        .await;
                        assert_eq!(caller.region_id(), expected_region);
                        states.lock().unwrap().push(input.request_state().map(str::to_owned));
                        answer_roots(input)
                    })
                },
            ))
            .await
            .unwrap();
            assert_eq!(pending_polls.load(Ordering::SeqCst), 3);
            assert_eq!(
                *states.lock().unwrap(),
                [Some("first".to_owned()), None, Some("third".to_owned())],
            );
            assert_eq!(installed_calls.load(Ordering::SeqCst), 0);
            let source = verb.completed_source(result);
            assert!(source.contains("7.30e-2"));
            let result: Value = serde_json::from_str(&source).unwrap();
            assert_eq!(result["com.example/receipt"], "résumé 東京");
            let requests = result["com.example/requests"].as_array().unwrap();
            assert_eq!(requests.len(), 4);
            let original = &requests[0]["params"];
            for (key, value) in verb.original().as_object().unwrap() {
                assert_eq!(&original[key], value);
            }
            assert_eq!(
                original["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"]["com.example/preserved"]["mode"],
                "read",
            );
            assert!(
                original["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"]
                    .get("io.modelcontextprotocol/tasks")
                    .is_none()
            );
            for (round, request) in requests.iter().enumerate() {
                assert_eq!(request["id"], round + 2);
                assert_eq!(request["method"], verb.method());
                let mut parameters = request["params"].clone();
                if round > 0 {
                    let expected_state = match round {
                        1 => Some(json!("first")),
                        2 => None,
                        3 => Some(json!("third")),
                        _ => unreachable!(),
                    };
                    let expected_answers = match round {
                        1 => Some(json!({"first": {"roots": []}})),
                        2 => Some(json!({"second": {"roots": []}})),
                        3 => None,
                        _ => unreachable!(),
                    };
                    assert_eq!(parameters.get("requestState"), expected_state.as_ref());
                    assert_eq!(parameters.get("inputResponses"), expected_answers.as_ref());
                    parameters.as_object_mut().unwrap().remove("requestState");
                    parameters.as_object_mut().unwrap().remove("inputResponses");
                }
                assert_eq!(&parameters, original);
            }
            assert_eq!(client.next_id.load(Ordering::SeqCst), 6);
            assert_eq!(client.final_result_cache_stats().fills, 0);
            client.close_with_cx(&cx).await.unwrap();
            assert!(client.child.is_none());
        }
    });
}

#[test]
fn stdio_async_mrtr_pending_cancel_deadline_or_drop_publishes_no_continuation() {
    struct ResponderDrop(Arc<AtomicUsize>);

    impl Drop for ResponderDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    run(|cx| async move {
        for stop in ["cancel", "deadline", "drop"] {
            let mut client = connected(
                &cx,
                builder(),
                REJECT_CONTINUATION,
                &[discovery(), response(2, roots_input(1, "pending")), tools(3)],
            )
            .await;
            let cancellation = McpRequestCancellation::new();
            let started = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let observed_started = Arc::clone(&started);
            let observed_dropped = Arc::clone(&dropped);
            {
                let mut waiting = pin!(Verb::Tool.call_async(
                    &mut client,
                    &cx,
                    &cancellation,
                    Instant::now() + Duration::from_secs(1),
                    move |caller, _| {
                        let started = Arc::clone(&observed_started);
                        let guard = ResponderDrop(Arc::clone(&observed_dropped));
                        Box::pin(async move {
                            let _guard = guard;
                            assert!(caller.blocking_pool_handle().is_none());
                            started.fetch_add(1, Ordering::SeqCst);
                            std::future::pending::<McpResult<MrtrInputResponses>>().await
                        })
                    },
                ));
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    if started.load(Ordering::SeqCst) == 1 {
                        Poll::Ready(())
                    } else {
                        task.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
                match stop {
                    "cancel" => {
                        cancellation.cancel();
                        assert_eq!(
                            waiting.await.unwrap_err().code,
                            McpErrorCode::RequestCancelled,
                        );
                    }
                    "deadline" => {
                        let error = waiting.await.unwrap_err();
                        assert_eq!(error.code, McpErrorCode::InternalError);
                        assert_eq!(error.data.as_ref().unwrap()["timeoutSource"], "absolute");
                    }
                    "drop" => {}
                    _ => unreachable!(),
                }
            }
            assert_eq!(started.load(Ordering::SeqCst), 1);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            // The peer accepts only tools/list after input_required. A spurious
            // continuation or cancellation for the already-retired RPC fails it.
            assert_reusable(&cx, &mut client, 3).await;
        }
    });
}

#[test]
fn stdio_async_mrtr_retains_resumed_authority_during_pending_callback_and_drop() {
    use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};

    struct ObserveDrop(Arc<Mutex<Option<bool>>>);

    impl Drop for ObserveDrop {
        fn drop(&mut self) {
            *self.0.lock().unwrap() =
                Cx::current().map(|current| current.capabilities().spawn);
        }
    }

    run(|cx| async move {
        let mut client = connected(
            &cx,
            builder(),
            REJECT_CONTINUATION,
            &[discovery(), response(2, roots_input(1, "pending")), tools(3)],
        )
        .await;
        assert!(Cx::current().unwrap().capabilities().spawn);
        let cancellation = McpRequestCancellation::new();
        let polls = Arc::new(Mutex::new(Vec::new()));
        let dropped = Arc::new(Mutex::new(None));
        let observed_polls = Arc::clone(&polls);
        let observed_drop = Arc::clone(&dropped);
        let mut operation = Box::pin(Verb::Tool.call_async(
            &mut client,
            &cx,
            &cancellation,
            Instant::now() + Duration::from_secs(5),
            move |caller, _| {
                let polls = Arc::clone(&observed_polls);
                let guard = ObserveDrop(Arc::clone(&observed_drop));
                Box::pin(async move {
                    let _guard = guard;
                    poll_fn(move |_| {
                        let current = Cx::current().unwrap();
                        assert_eq!(current.task_id(), caller.task_id());
                        assert_eq!(current.region_id(), caller.region_id());
                        polls.lock().unwrap().push(current.capabilities().spawn);
                        Poll::<McpResult<MrtrInputResponses>>::Pending
                    })
                    .await
                })
            },
        ));
        poll_fn(|task| {
            assert!(operation.as_mut().poll(task).is_pending());
            if polls.lock().unwrap().is_empty() {
                task.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        assert_eq!(*polls.lock().unwrap(), [true]);
        assert_eq!(*dropped.lock().unwrap(), None);

        poll_fn(|task| {
            let restriction =
                Cx::push_restriction(CapSet::<false, true, true, true, true>::MASK);
            assert!(operation.as_mut().poll(task).is_pending());
            assert_eq!(*polls.lock().unwrap(), [true, false]);
            drop(restriction);
            assert!(Cx::current().unwrap().capabilities().spawn);

            // A wider host must not restore a permission removed while the
            // same callback was pending.
            assert!(operation.as_mut().poll(task).is_pending());
            assert_eq!(*polls.lock().unwrap(), [true, false, false]);
            Poll::Ready(())
        })
        .await;
        assert!(Cx::current().unwrap().capabilities().spawn);
        drop(operation);
        assert_eq!(*dropped.lock().unwrap(), Some(false));
        assert!(Cx::current().unwrap().capabilities().spawn);
        assert!(cx.capabilities().spawn);
        // Abandoning the callback sends neither a retry nor a cancellation
        // for the already-retired RPC, and leaves the connection usable.
        assert_reusable(&cx, &mut client, 3).await;
    });
}

#[test]
fn stdio_async_mrtr_rejects_whole_batch_invalid_maps_and_same_poll_cancellation() {
    run(|cx| async move {
        for case in ["unadvertised", "missing", "extra", "cancel-ready", "error"] {
            let mut challenge = roots_input(1, "not-replayed");
            if case == "unadvertised" {
                challenge["inputRequests"]["z-unadvertised"] = json!({
                    "method": "elicitation/create",
                    "params": {
                        "mode": "form", "message": "Approve",
                        "requestedSchema": {"type": "object", "properties": {}},
                    },
                });
            }
            let mut client = connected(
                &cx,
                builder(),
                REJECT_CONTINUATION,
                &[discovery(), response(2, challenge), tools(3)],
            )
            .await;
            let cancellation = McpRequestCancellation::new();
            let callback_cancellation = cancellation.clone();
            let calls = Arc::new(AtomicUsize::new(0));
            let observed_calls = Arc::clone(&calls);
            let error = Verb::Tool
                .call_async(
                    &mut client,
                    &cx,
                    &cancellation,
                    Instant::now() + Duration::from_secs(5),
                    move |_, input| {
                        observed_calls.fetch_add(1, Ordering::SeqCst);
                        let cancellation = callback_cancellation.clone();
                        Box::pin(async move {
                            let mut yielded = false;
                            poll_fn(|task| {
                                if yielded {
                                    Poll::Ready(())
                                } else {
                                    yielded = true;
                                    task.waker().wake_by_ref();
                                    Poll::Pending
                                }
                            })
                            .await;
                            match case {
                                "missing" | "unadvertised" => Ok(MrtrInputResponses::new()),
                                "extra" => {
                                    let mut responses = answer_roots(input)?;
                                    responses.insert("foreign".to_owned(), json!({"roots": []}));
                                    Ok(responses)
                                }
                                "cancel-ready" => {
                                    cancellation.cancel();
                                    answer_roots(input)
                                }
                                "error" => Err(McpError::invalid_request("host declined input")),
                                _ => unreachable!(),
                            }
                        })
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(
                calls.load(Ordering::SeqCst),
                usize::from(case != "unadvertised"),
                "{case}",
            );
            assert_eq!(
                error.code,
                match case {
                    "unadvertised" | "error" => McpErrorCode::InvalidRequest,
                    "missing" | "extra" => McpErrorCode::InvalidParams,
                    "cancel-ready" => McpErrorCode::RequestCancelled,
                    _ => unreachable!(),
                },
                "{case}: {error:?}",
            );
            assert_reusable(&cx, &mut client, 3).await;
        }
    });
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn stdio_async_mrtr_legacy_result_does_not_invoke_responder() {
    const SCRIPT: &str = r#"
IFS= read -r initialize || exit 80
case "$initialize" in *'"method":"initialize"'*2024-11-05*) ;; *) exit 81;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"legacy-async-responder","version":"1"}}}'
IFS= read -r initialized || exit 82
case "$initialized" in *'"method":"notifications/initialized"'*) ;; *) exit 83;; esac
IFS= read -r request || exit 84
case "$request" in *'"method":"tools/call"'*) ;; *) exit 85;; esac
case "$request" in *io.modelcontextprotocol/protocolVersion*|*inputResponses*|*requestState*) exit 86;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"legacy result"}],"isError":false}}'
IFS= read -r unexpected && exit 87
exit 0
"#;
    run(|cx| async move {
        let mut client = connected(
            &cx,
            ClientBuilder::new()
                .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly))
                .max_retries(0),
            SCRIPT,
            &[],
        )
        .await;
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let result = Verb::Tool
            .call_async(
                &mut client,
                &cx,
                &McpRequestCancellation::new(),
                Instant::now() + Duration::from_secs(5),
                move |_, _| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async { Ok(MrtrInputResponses::new()) })
                },
            )
            .await
            .unwrap();
        let CoreResult::Legacy(LegacyCoreResult::ToolsCall(result)) = result else {
            panic!("exact legacy results must keep their selected result family");
        };
        assert_eq!(serde_json::to_value(result).unwrap()["content"][0]["text"], "legacy result");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(client.next_id.load(Ordering::SeqCst), 3);
        client.close_with_cx(&cx).await.unwrap();
        assert!(client.child.is_none());
    });
}
