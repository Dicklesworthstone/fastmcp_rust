//! Native subprocess coverage for caller-owned, cooperative MRTR responders.

use std::collections::HashMap;
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
