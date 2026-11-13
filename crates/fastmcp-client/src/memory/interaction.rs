//! Caller-owned MRTR interaction over the existing bounded memory executor.
//!
//! Installed handlers are frozen before discovery and advertise only their
//! modern capability leaves. The shared MRTR driver admits the entire input
//! batch before host effects and keeps every callback and continuation inside
//! the original cancellation domain and absolute deadline. Low-level core
//! execution and explicit Tasks calls remain single-request operations.

use std::collections::HashMap;

use asupersync::Cx;
use fastmcp_core::{McpRequestCancellation, McpResult};
use fastmcp_protocol::{CoreResult, FINAL_CLIENT_CAPABILITIES_META_KEY};
use serde_json::Value;

use super::{MemoryClient, MemoryClientBuilder, checkpoint};
use crate::execution::{MrtrDriver, MrtrDriverLimits};
use crate::{
    MAX_MRTR_CONTINUATION_ROUNDS, MAX_MRTR_TOTAL_INPUT_RESPONSES, ReverseRequestHandlers,
    check_mrtr_operation, mrtr_input_required_for_method, mrtr_operation_deadline,
    mrtr_retry_parameters, wait_for_mrtr_operation,
};

impl MemoryClientBuilder {
    /// Installs modern sampling, roots, and elicitation handlers before discovery.
    ///
    /// The installed modern handlers contribute their capabilities once, when
    /// connecting. Explicit capability settings still restrict optional leaves
    /// such as sampling tools or an elicitation mode. Legacy callbacks do not
    /// advertise or execute on this modern-only connection.
    ///
    /// `call_tool`, `read_resource`, and `get_prompt` may then follow admitted
    /// input-required results. A complete batch must be supported before any
    /// handler runs. `request_core`, owned executions, and explicit Tasks calls
    /// continue to return each result directly without implicit continuation.
    #[must_use]
    pub fn reverse_request_handlers(mut self, handlers: ReverseRequestHandlers) -> Self {
        self.reverse_request_handlers = handlers;
        self
    }
}

impl MemoryClient {
    /// Reads a resource, fulfilling input-required results through installed handlers.
    ///
    /// The original caller context, cancellation token, absolute deadline, and
    /// resource URI remain bound across all rounds. Without installed modern
    /// handlers, an input-required result is returned directly to the caller.
    /// Complete first-round results honor the connection's cache policy;
    /// input-required results and every continuation remain uncached.
    pub async fn read_resource(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        uri: &str,
    ) -> McpResult<CoreResult> {
        self.follow_installed_mrtr(
            cx,
            cancellation,
            "resources/read",
            serde_json::json!({"uri": uri}),
        )
        .await
    }

    /// Gets a prompt with the same bounded MRTR lifecycle as a tool or resource.
    ///
    /// Continuations retain the original name and arguments, and carry only
    /// the latest input responses and opaque request state. Failed requests
    /// are never retried automatically.
    pub async fn get_prompt(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<CoreResult> {
        self.follow_installed_mrtr(
            cx,
            cancellation,
            "prompts/get",
            serde_json::json!({"name": name, "arguments": arguments}),
        )
        .await
    }

    pub(super) async fn follow_installed_mrtr(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        original_parameters: Value,
    ) -> McpResult<CoreResult> {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        let handlers = self.reverse_request_handlers.clone();
        if !handlers.has_modern_handlers() {
            return self
                .cached_core_request(cx, cancellation, method, original_parameters, true)
                .await
                .map(|(result, _)| result);
        }
        let deadline = mrtr_operation_deadline(cx, self.timeout_policy)?;
        let mut driver = MrtrDriver::new(
            cx,
            deadline,
            MrtrDriverLimits::new(MAX_MRTR_CONTINUATION_ROUNDS, MAX_MRTR_TOTAL_INPUT_RESPONSES)?,
        )?;
        // Freeze the exact capability leaves transmitted on the original
        // request. A peer descriptor or a handler's presence never grants a
        // capability the request withheld. This ordinary path excludes Tasks.
        let original_parameters = self.parameters_with_tasks(original_parameters, false)?;
        let capabilities = original_parameters["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY].clone();
        wait_for_mrtr_operation(cx, Some(cancellation), deadline, async {
            let mut parameters = original_parameters.clone();
            let mut first_round = true;
            loop {
                driver.before_request()?;
                let result = if first_round {
                    first_round = false;
                    self.cached_core_request(cx, cancellation, method, parameters, true)
                        .await?
                        .0
                } else {
                    self.request_core(cx, cancellation, method, parameters)
                        .await?
                };
                check_mrtr_operation(cx, Some(cancellation), deadline)?;
                let Some(input_required) = mrtr_input_required_for_method(method, &result) else {
                    return Ok(result);
                };
                driver.begin_continuation()?;
                driver.admit_input_responses(
                    input_required
                        .input_requests()
                        .map_or(0, |requests| requests.members().len()),
                )?;
                let responses = handlers
                    .respond_to_input_required_async(cx, &capabilities, input_required, || {
                        check_mrtr_operation(cx, Some(cancellation), deadline)
                    })
                    .await?;
                parameters =
                    mrtr_retry_parameters(original_parameters.clone(), input_required, responses)?;
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, poll_fn};
    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Poll;
    use std::time::Duration;

    use asupersync::runtime::RuntimeBuilder;
    use fastmcp_core::McpErrorCode;
    use fastmcp_protocol::{
        ClientCapabilities, ClientInfo, FinalCoreResult, JsonRpcMessage, JsonRpcRequest,
        JsonRpcResponse, RequestId,
    };
    use fastmcp_transport::memory::{MemoryTransport, create_memory_transport_pair_with_capacity};
    use serde_json::json;

    use super::*;
    use crate::memory::{MemoryRequestEvent, MemoryRequestExecution};
    use crate::{FinalEmbeddedRootsListResult, RequestTimeoutPolicy, ReverseRequestCancellation};

    fn run<F: Future<Output = ()>>(test: impl FnOnce(Cx) -> F) {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(cx.blocking_pool_handle().is_none());
            asupersync::time::timeout(cx.now(), Duration::from_secs(8), test(cx))
                .await
                .expect("memory MRTR must make progress on its caller's runtime");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    fn builder() -> MemoryClientBuilder {
        MemoryClient::builder(ClientInfo {
            name: "memory-interaction-client".to_owned(),
            version: "1".to_owned(),
        })
    }

    fn response(id: i64, result: Value) -> JsonRpcMessage {
        JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), result))
    }

    fn tools() -> Value {
        json!({"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"})
    }

    fn input(state: &str) -> Value {
        json!({
            "resultType": "input_required",
            "requestState": state,
            "inputRequests": {"roots": {"method": "roots/list"}},
        })
    }

    async fn receive(
        cx: &Cx,
        peer: &mut MemoryTransport,
        method: &str,
        id: i64,
    ) -> JsonRpcRequest {
        let JsonRpcMessage::Request(request) = peer.recv_async(cx).await.unwrap() else {
            panic!("expected one client request");
        };
        assert_eq!(request.method, method);
        assert_eq!(request.id, Some(RequestId::Number(id)));
        request
    }

    async fn connected(
        cx: &Cx,
        builder: MemoryClientBuilder,
        extensions: Value,
    ) -> (MemoryClient, MemoryTransport) {
        let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
        peer.send_async(
            cx,
            &response(1, json!({
                "resultType":"complete", "supportedVersions":["2026-07-28"],
                "capabilities":{"extensions":extensions}, "ttlMs":0, "cacheScope":"private",
            })),
        )
        .await
        .unwrap();
        let client = builder.connect(cx, transport).await.unwrap();
        let discovery = receive(cx, &mut peer, "server/discover", 1).await;
        assert!(discovery.params.unwrap()["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]
            .get("roots")
            .is_some());
        (client, peer)
    }

    fn roots_handler(calls: &Arc<AtomicUsize>) -> ReverseRequestHandlers {
        let calls = Arc::clone(calls);
        ReverseRequestHandlers::new().with_modern_roots_list(move |cx, _, _| {
            assert!(cx.blocking_pool_handle().is_none());
            calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: Vec::new() }) })
        })
    }

    async fn finish(
        cx: &Cx,
        client: &mut MemoryClient,
        execution: &mut MemoryRequestExecution,
    ) -> CoreResult {
        loop {
            match client
                .next_event(cx, &McpRequestCancellation::new(), execution)
                .await
                .unwrap()
            {
                Some(MemoryRequestEvent::Notification(_)) => {}
                Some(MemoryRequestEvent::Result(result)) => return *result,
                None => panic!("the independent request must retain its result"),
            }
        }
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
                Self::Tool => json!({"name":"interactive", "arguments":{"value":"résumé 東京"}}),
                Self::Resource => json!({"uri":"file:///interaction-resource"}),
                Self::Prompt => json!({"name":"interactive", "arguments":{"value":"résumé 東京"}}),
            }
        }

        fn completed(self) -> Value {
            let mut result = match self {
                Self::Tool => json!({"resultType":"complete", "content":[]}),
                Self::Resource => json!({
                    "resultType":"complete", "contents":[], "ttlMs":0, "cacheScope":"private",
                }),
                Self::Prompt => json!({"resultType":"complete", "messages":[]}),
            };
            result["com.example/receipt"] = json!({"value":"résumé 東京"});
            result["com.example/receipt"]["exact"] = Value::Number(
                serde_json::Number::from_string_unchecked("7.30e-2".to_owned()),
            );
            result
        }

        async fn call(
            self,
            cx: &Cx,
            client: &mut MemoryClient,
            cancellation: &McpRequestCancellation,
        ) -> McpResult<CoreResult> {
            match self {
                Self::Tool => client
                    .call_tool(cx, cancellation, "interactive", json!({"value":"résumé 東京"}))
                    .await,
                Self::Resource => client
                    .read_resource(cx, cancellation, "file:///interaction-resource")
                    .await,
                Self::Prompt => client
                    .get_prompt(
                        cx,
                        cancellation,
                        "interactive",
                        HashMap::from([("value".to_owned(), "résumé 東京".to_owned())]),
                    )
                    .await,
            }
        }

        fn assert_completed(self, result: CoreResult) {
            // `encode_complete_result`, not `serde_json::to_string`.
            // `CompleteResult<T>` derives only Debug + Clone -- deliberately,
            // because serde cannot carry what this test asserts. The exact
            // number `7.30e-2` survives only through the ExactJsonValue
            // algebra; a serde round trip would re-emit it as `0.073` and the
            // `contains("7.30e-2")` assertion below would fail even though the
            // product had preserved it correctly. `Vec::new()` / `&[]` claim no
            // known members, which is the shape every other call site in this
            // crate uses (core_listen.rs:95/406, tasks/listen.rs:122/386), and
            // it is right here because `com.example/receipt` is an unknown
            // top-level member and therefore rides in `extras`.
            // A generic `fn`, not a closure: the three arms carry three
            // different payload types and a closure is monomorphic, so one
            // closure cannot serve all three.
            fn encode<T>(result: &fastmcp_protocol::CompleteResult<T>) -> String {
                fastmcp_protocol::encode_complete_result(
                    &result.meta,
                    Vec::new(),
                    &[],
                    &result.extras,
                )
                .expect("a decoded complete result re-encodes")
            }
            let source = match (self, result) {
                (Self::Tool, CoreResult::Final(FinalCoreResult::ToolsCall { result, .. })) =>
                    encode(&result),
                (Self::Resource, CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. })) =>
                    encode(&result),
                (Self::Prompt, CoreResult::Final(FinalCoreResult::PromptsGet { result, .. })) =>
                    encode(&result),
                _ => panic!("MRTR must preserve its exact method result family"),
            };
            let result: Value = serde_json::from_str(&source).unwrap();
            assert_eq!(result["com.example/receipt"]["value"], "résumé 東京");
            assert!(source.contains("7.30e-2"));
        }
    }

    #[test]
    fn memory_cache_resource_reads_invalidate_on_queued_resource_and_catalog_changes() {
        run(|cx| async move {
            for notification_method in [
                "notifications/resources/updated",
                "notifications/resources/list_changed",
            ] {
                let (mut client, mut peer) = connected(&cx, builder(), json!({})).await;
                let token = McpRequestCancellation::new();
                let mut complete = Verb::Resource.completed();
                complete["ttlMs"] = json!(60_000);
                for (id, uri) in [(2, "file:///one"), (3, "file:///two")] {
                    peer.send_async(&cx, &response(id, complete.clone()))
                        .await
                        .unwrap();
                    Verb::Resource
                        .assert_completed(client.read_resource(&cx, &token, uri).await.unwrap());
                    assert_eq!(
                        receive(&cx, &mut peer, "resources/read", id)
                            .await
                            .params
                            .unwrap()["uri"],
                        uri
                    );
                    Verb::Resource
                        .assert_completed(client.read_resource(&cx, &token, uri).await.unwrap());
                }
                assert_eq!(client.next_id, 4);
                assert_eq!(client.final_result_cache_stats().hits, 2);
                peer.send_async(
                    &cx,
                    &JsonRpcMessage::Request(JsonRpcRequest::notification(
                        notification_method,
                        Some(if notification_method.ends_with("/updated") {
                            json!({"uri":"file:///one"})
                        } else {
                            json!({})
                        }),
                    )),
                )
                .await
                .unwrap();
                let mut serving = cx
                    .spawn(move |peer_cx| async move {
                        for (id, uri) in [(4, "file:///one"), (5, "file:///two")] {
                            assert_eq!(
                                receive(&peer_cx, &mut peer, "resources/read", id)
                                    .await
                                    .params
                                    .unwrap()["uri"],
                                uri
                            );
                            peer.send_async(&peer_cx, &response(id, complete.clone()))
                                .await
                                .unwrap();
                        }
                        peer
                    })
                    .unwrap();
                // The bounded cache uses a shared resource-read generation;
                // no old URI survives either accepted resource invalidation.
                for uri in ["file:///one", "file:///two"] {
                    Verb::Resource
                        .assert_completed(client.read_resource(&cx, &token, uri).await.unwrap());
                }
                assert_eq!(client.final_result_cache_stats().hits, 2);
                assert_eq!(client.take_server_notifications().len(), 1);
                let _peer = serving.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_cache_prompt_get_and_input_required_cache_lookalikes_remain_uncached() {
        run(|cx| async move {
            for verb in [Verb::Resource, Verb::Prompt] {
                let (mut client, mut peer) = connected(&cx, builder(), json!({})).await;
                let token = McpRequestCancellation::new();
                for id in 2..=3 {
                    let result = match verb {
                        Verb::Resource => json!({
                            "resultType":"input_required", "requestState":"manual",
                            "ttlMs":60_000, "cacheScope":"public", "nextCursor":"inert",
                        }),
                        Verb::Prompt => json!({
                            "resultType":"complete", "messages":[],
                            "ttlMs":60_000, "cacheScope":"public", "nextCursor":"inert",
                        }),
                        Verb::Tool => unreachable!(),
                    };
                    peer.send_async(&cx, &response(id, result)).await.unwrap();
                    let result = verb.call(&cx, &mut client, &token).await.unwrap();
                    assert!(matches!(
                        result,
                        CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { .. })
                            | CoreResult::Final(FinalCoreResult::PromptsGet { .. })
                    ));
                    receive(&cx, &mut peer, verb.method(), id).await;
                }
                assert_eq!(client.final_result_cache_stats().fills, 0);
                assert_eq!(client.final_result_cache_stats().hits, 0);
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_cache_mrtr_continuation_results_and_raw_requests_do_not_fill() {
        run(|cx| async move {
            let calls = Arc::new(AtomicUsize::new(0));
            let (mut client, mut peer) = connected(
                &cx,
                builder().reverse_request_handlers(roots_handler(&calls)),
                json!({}),
            )
            .await;
            let mut serving = cx
                .spawn(move |peer_cx| async move {
                    let mut complete = Verb::Resource.completed();
                    complete["ttlMs"] = json!(60_000);
                    for first_id in [2, 4] {
                        let original =
                            receive(&peer_cx, &mut peer, "resources/read", first_id).await;
                        assert!(original.params.unwrap().get("requestState").is_none());
                        peer.send_async(&peer_cx, &response(first_id, input("once-per-operation")))
                            .await
                            .unwrap();
                        let continuation =
                            receive(&peer_cx, &mut peer, "resources/read", first_id + 1).await;
                        assert_eq!(
                            continuation.params.unwrap()["requestState"],
                            "once-per-operation"
                        );
                        peer.send_async(&peer_cx, &response(first_id + 1, complete.clone()))
                            .await
                            .unwrap();
                    }
                    for id in 6..=7 {
                        receive(&peer_cx, &mut peer, "resources/read", id).await;
                        peer.send_async(&peer_cx, &response(id, complete.clone()))
                            .await
                            .unwrap();
                    }
                    peer
                })
                .unwrap();
            let token = McpRequestCancellation::new();
            for _ in 0..2 {
                Verb::Resource
                    .assert_completed(Verb::Resource.call(&cx, &mut client, &token).await.unwrap());
            }
            assert_eq!(
                calls.load(Ordering::Acquire),
                2,
                "a prior continuation cannot suppress a later interaction"
            );
            for _ in 0..2 {
                client
                    .request_core(&cx, &token, "resources/read", Verb::Resource.original())
                    .await
                    .unwrap();
            }
            assert_eq!(client.final_result_cache_stats().fills, 0);
            assert_eq!(client.final_result_cache_stats().hits, 0);
            assert_eq!(client.next_id, 8);
            let _peer = serving.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_mrtr_all_verbs_preserve_original_parameters_and_replace_round_state() {
        run(|cx| async move {
            for verb in [Verb::Tool, Verb::Resource, Verb::Prompt] {
                let calls = Arc::new(AtomicUsize::new(0));
                let (mut client, mut peer) = connected(
                    &cx,
                    builder().reverse_request_handlers(roots_handler(&calls)),
                    json!({}),
                )
                .await;
                let mut serving = cx.spawn(move |peer_cx| async move {
                    let original = receive(&peer_cx, &mut peer, verb.method(), 2).await;
                    let original = original.params.unwrap();
                    let mut plain = original.clone();
                    plain.as_object_mut().unwrap().remove("_meta");
                    assert_eq!(plain, verb.original());
                    assert_eq!(
                        original["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
                        "memory-interaction-client",
                    );
                    peer.send_async(&peer_cx, &response(2, input("first-state")))
                        .await
                        .unwrap();

                    let first = receive(&peer_cx, &mut peer, verb.method(), 3).await;
                    let mut expected = original.clone();
                    expected["requestState"] = json!("first-state");
                    expected["inputResponses"] = json!({"roots":{"roots":[]}});
                    assert_eq!(first.params.unwrap(), expected);
                    peer.send_async(&peer_cx, &response(3, json!({
                        "resultType":"input_required", "requestState":"second-state",
                    })))
                    .await
                    .unwrap();

                    let second = receive(&peer_cx, &mut peer, verb.method(), 4).await;
                    let mut expected = original;
                    expected["requestState"] = json!("second-state");
                    assert_eq!(second.params.unwrap(), expected,
                        "a state-only round must not replay old input responses");
                    peer.send_async(&peer_cx, &response(4, verb.completed()))
                        .await
                        .unwrap();
                    peer
                }).unwrap();
                let result = verb.call(&cx, &mut client, &McpRequestCancellation::new())
                    .await
                    .unwrap();
                verb.assert_completed(result);
                assert_eq!(calls.load(Ordering::Acquire), 1);
                assert_eq!(client.next_id, 5);
                let _peer = serving.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
                assert!(cx.checkpoint().is_ok());
            }
        });
    }

    #[test]
    fn memory_mrtr_without_handlers_returns_input_required_for_manual_continuation() {
        run(|cx| async move {
            for verb in [Verb::Tool, Verb::Resource, Verb::Prompt] {
                let capabilities = serde_json::from_value(json!({"roots":{}})).unwrap();
                let (mut client, mut peer) = connected(
                    &cx, builder().capabilities(capabilities), json!({}),
                ).await;
                let mut serving = cx.spawn(move |peer_cx| async move {
                    receive(&peer_cx, &mut peer, verb.method(), 2).await;
                    peer.send_async(&peer_cx, &response(2, input("manual-state")))
                        .await.unwrap();
                    receive(&peer_cx, &mut peer, "tools/list", 3).await;
                    peer.send_async(&peer_cx, &response(3, tools())).await.unwrap();
                    peer
                }).unwrap();
                let cancellation = McpRequestCancellation::new();
                let result = verb.call(&cx, &mut client, &cancellation).await.unwrap();
                let required = match (verb, result) {
                    (Verb::Tool, CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { result, .. }))
                    | (Verb::Resource, CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { result, .. }))
                    | (Verb::Prompt, CoreResult::Final(FinalCoreResult::PromptsGetInputRequired { result, .. })) => result,
                    _ => panic!("unconfigured clients retain the typed input-required result"),
                };
                assert_eq!(required.request_state(), Some("manual-state"));
                assert_eq!(client.next_id, 3);
                client.list_tools(&cx, &cancellation, None).await.unwrap();
                let _peer = serving.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_mrtr_admits_the_complete_input_batch_before_any_handler_effect() {
        run(|cx| async move {
            // The first case has an unadvertised capability; the second
            // advertises it for manual resolution but installs no handler.
            // Neither may invoke the otherwise valid roots sibling first.
            for advertise_sampling in [false, true] {
                let calls = Arc::new(AtomicUsize::new(0));
                let capabilities: ClientCapabilities = serde_json::from_value(
                    if advertise_sampling { json!({"sampling":{}}) } else { json!({}) },
                ).unwrap();
                let (mut client, mut peer) = connected(
                    &cx,
                    builder().capabilities(capabilities)
                        .reverse_request_handlers(roots_handler(&calls)),
                    json!({}),
                ).await;
                let cancellation = McpRequestCancellation::new();
                let mut sibling = client.execute_core(&cx, &cancellation, "tools/list", json!({}))
                    .await.unwrap();
                receive(&cx, &mut peer, "tools/list", 2).await;
                let mut serving = cx.spawn(move |peer_cx| async move {
                    receive(&peer_cx, &mut peer, "tools/call", 3).await;
                    peer.send_async(&peer_cx, &response(2, tools())).await.unwrap();
                    peer.send_async(&peer_cx, &response(3, json!({
                        "resultType":"input_required", "requestState":"not-replayed",
                        "inputRequests":{
                            "a-roots":{"method":"roots/list"},
                            "z-sampling":{"method":"sampling/createMessage","params":{
                                "messages":[{"role":"user","content":{"type":"text","text":"hello"}}],
                                "maxTokens":16,
                            }},
                        },
                    }))).await.unwrap();
                    receive(&peer_cx, &mut peer, "tools/list", 4).await;
                    peer.send_async(&peer_cx, &response(4, tools())).await.unwrap();
                    peer
                }).unwrap();
                let error = client.call_tool(&cx, &cancellation, "interactive", json!({}))
                    .await.unwrap_err();
                assert_eq!(error.code, if advertise_sampling {
                    McpErrorCode::InvalidParams
                } else {
                    McpErrorCode::InvalidRequest
                });
                assert_eq!(calls.load(Ordering::Acquire), 0);
                assert!(matches!(finish(&cx, &mut client, &mut sibling).await,
                    CoreResult::Final(FinalCoreResult::ToolsList { .. })));
                assert!(matches!(client.list_tools(&cx, &cancellation, None).await.unwrap(),
                    CoreResult::Final(FinalCoreResult::ToolsList { .. })));
                assert_eq!(client.next_id, 5, "refusal must allocate no continuation ID");
                let _peer = serving.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_mrtr_callback_cancellation_and_panic_cannot_publish_a_continuation() {
        #[derive(Clone, Copy)]
        enum Stop {
            ConstructorCancel,
            PollCancel,
            ConstructorPanic,
            PollPanic,
        }
        run(|cx| async move {
            for stop in [Stop::ConstructorCancel, Stop::PollCancel, Stop::ConstructorPanic, Stop::PollPanic] {
                let calls = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&calls);
                let cancellation = McpRequestCancellation::new();
                let stop_request = cancellation.clone();
                let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, _, _| {
                    observed.fetch_add(1, Ordering::AcqRel);
                    if matches!(stop, Stop::ConstructorCancel) {
                        stop_request.cancel();
                    }
                    assert!(!matches!(stop, Stop::ConstructorPanic), "private constructor failure");
                    let stop_request = stop_request.clone();
                    Box::pin(async move {
                        if matches!(stop, Stop::PollCancel) {
                            stop_request.cancel();
                        }
                        assert!(!matches!(stop, Stop::PollPanic), "private poll failure");
                        Ok(FinalEmbeddedRootsListResult { roots: Vec::new() })
                    })
                });
                let (mut client, mut peer) = connected(
                    &cx, builder().reverse_request_handlers(handlers), json!({}),
                ).await;
                let mut serving = cx.spawn(move |peer_cx| async move {
                    receive(&peer_cx, &mut peer, "tools/call", 2).await;
                    peer.send_async(&peer_cx, &response(2, input("private-state")))
                        .await.unwrap();
                    let reused = receive(&peer_cx, &mut peer, "tools/list", 3).await;
                    assert!(reused.params.unwrap().get("requestState").is_none());
                    peer.send_async(&peer_cx, &response(3, tools())).await.unwrap();
                    peer
                }).unwrap();
                let error = client.call_tool(&cx, &cancellation, "interactive", json!({}))
                    .await.unwrap_err();
                if matches!(stop, Stop::ConstructorCancel | Stop::PollCancel) {
                    assert_eq!(error.code, McpErrorCode::RequestCancelled);
                } else {
                    assert_eq!(error.code, McpErrorCode::InternalError);
                    assert_eq!(error.message, "Client reverse request handler failed");
                    assert!(error.data.is_none());
                }
                assert_eq!(calls.load(Ordering::Acquire), 1);
                assert_eq!(client.next_id, 3);
                assert!(cx.checkpoint().is_ok());
                client.list_tools(&cx, &McpRequestCancellation::new(), None).await.unwrap();
                let _peer = serving.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
            }
        });
    }

    struct CallbackDrop {
        dropped: Arc<AtomicUsize>,
        cancelled: Arc<AtomicUsize>,
        token: ReverseRequestCancellation,
    }

    impl Drop for CallbackDrop {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::AcqRel);
            if self.token.is_cancel_requested() {
                self.cancelled.fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    #[test]
    fn memory_mrtr_pending_callback_is_owned_through_cancel_drop_and_deadline() {
        #[derive(Clone, Copy)]
        enum Stop {
            Cancel,
            Drop,
            Deadline,
        }
        run(|cx| async move {
            for stop in [Stop::Cancel, Stop::Drop, Stop::Deadline] {
                let entered = Arc::new(AtomicUsize::new(0));
                let dropped = Arc::new(AtomicUsize::new(0));
                let cancelled = Arc::new(AtomicUsize::new(0));
                let observed_entered = Arc::clone(&entered);
                let observed_dropped = Arc::clone(&dropped);
                let observed_cancelled = Arc::clone(&cancelled);
                let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, token, _| {
                    let guard = CallbackDrop {
                        dropped: Arc::clone(&observed_dropped),
                        cancelled: Arc::clone(&observed_cancelled),
                        token,
                    };
                    let entered = Arc::clone(&observed_entered);
                    Box::pin(async move {
                        let _guard = guard;
                        entered.fetch_add(1, Ordering::AcqRel);
                        // No self-wake: the enclosing operation must retain
                        // its own cancellation and deadline observation.
                        std::future::pending::<McpResult<FinalEmbeddedRootsListResult>>().await
                    })
                });
                let builder = builder().reverse_request_handlers(handlers);
                let builder = if matches!(stop, Stop::Deadline) {
                    builder.timeout_policy(RequestTimeoutPolicy::new(
                        Duration::from_millis(300), Duration::from_millis(300),
                    ).unwrap()).unwrap()
                } else {
                    builder
                };
                let (mut client, mut peer) = connected(&cx, builder, json!({})).await;
                let mut serving = cx.spawn(move |peer_cx| async move {
                    receive(&peer_cx, &mut peer, "tools/call", 2).await;
                    peer.send_async(&peer_cx, &response(2, input("not-replayed")))
                        .await.unwrap();
                    receive(&peer_cx, &mut peer, "tools/list", 3).await;
                    peer.send_async(&peer_cx, &response(3, tools())).await.unwrap();
                    peer
                }).unwrap();
                let cancellation = McpRequestCancellation::new();
                {
                    let mut operation = pin!(client.call_tool(
                        &cx, &cancellation, "interactive", json!({}),
                    ));
                    poll_fn(|task| {
                        assert!(operation.as_mut().poll(task).is_pending());
                        if entered.load(Ordering::Acquire) == 1 {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    }).await;
                    match stop {
                        Stop::Drop => {}
                        Stop::Cancel => {
                            cancellation.cancel();
                            assert_eq!(operation.await.unwrap_err().code, McpErrorCode::RequestCancelled);
                        }
                        Stop::Deadline => {
                            let error = operation.await.unwrap_err();
                            assert_eq!(error.code, McpErrorCode::InternalError);
                            assert!(error.message.contains("deadline"));
                        }
                    }
                }
                assert_eq!(dropped.load(Ordering::Acquire), 1);
                assert_eq!(cancelled.load(Ordering::Acquire), 1,
                    "the handler sees cancellation before its future is destroyed");
                assert_eq!(client.next_id, 3);
                assert!(cx.checkpoint().is_ok());
                client.list_tools(&cx, &McpRequestCancellation::new(), None).await.unwrap();
                let _peer = serving.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_mrtr_round_bound_stops_before_an_extra_callback_or_request() {
        run(|cx| async move {
            let calls = Arc::new(AtomicUsize::new(0));
            let (mut client, mut peer) = connected(
                &cx, builder().reverse_request_handlers(roots_handler(&calls)), json!({}),
            ).await;
            let mut serving = cx.spawn(move |peer_cx| async move {
                for round in 0..=MAX_MRTR_CONTINUATION_ROUNDS {
                    let id = i64::try_from(round).unwrap() + 2;
                    receive(&peer_cx, &mut peer, "tools/call", id).await;
                    peer.send_async(&peer_cx, &response(id, input(&format!("round-{round}"))))
                        .await.unwrap();
                }
                let id = i64::try_from(MAX_MRTR_CONTINUATION_ROUNDS).unwrap() + 3;
                receive(&peer_cx, &mut peer, "tools/list", id).await;
                peer.send_async(&peer_cx, &response(id, tools())).await.unwrap();
                peer
            }).unwrap();
            let cancellation = McpRequestCancellation::new();
            let error = client.call_tool(&cx, &cancellation, "interactive", json!({}))
                .await.unwrap_err();
            assert_eq!(error.code, McpErrorCode::InvalidParams);
            assert!(error.message.contains("continuation-round limit"));
            assert_eq!(calls.load(Ordering::Acquire), MAX_MRTR_CONTINUATION_ROUNDS);
            assert_eq!(client.next_id, i64::try_from(MAX_MRTR_CONTINUATION_ROUNDS).unwrap() + 3);
            client.list_tools(&cx, &cancellation, None).await.unwrap();
            let _peer = serving.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[cfg(feature = "tasks")]
    #[test]
    fn memory_mrtr_handlers_do_not_implicitly_continue_explicit_task_calls() {
        use crate::FinalToolCallOutcome;

        run(|cx| async move {
            let calls = Arc::new(AtomicUsize::new(0));
            let (mut client, mut peer) = connected(
                &cx,
                builder().reverse_request_handlers(roots_handler(&calls)).with_tasks(),
                json!({"io.modelcontextprotocol/tasks":{}}),
            ).await;
            let mut serving = cx.spawn(move |peer_cx| async move {
                let request = receive(&peer_cx, &mut peer, "tools/call", 2).await;
                assert_eq!(
                    request.params.unwrap()["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
                    json!({"io.modelcontextprotocol/tasks":{}}),
                );
                peer.send_async(&peer_cx, &response(2, input("caller-owned-task-continuation")))
                    .await.unwrap();
                receive(&peer_cx, &mut peer, "tools/list", 3).await;
                peer.send_async(&peer_cx, &response(3, tools())).await.unwrap();
                peer
            }).unwrap();
            let cancellation = McpRequestCancellation::new();
            let FinalToolCallOutcome::InputRequired(input) = client
                .call_tool_final_outcome(&cx, &cancellation, "interactive-task", json!({}))
                .await.unwrap()
            else {
                panic!("explicit Tasks calls retain their manual continuation boundary");
            };
            assert_eq!(input.request_state(), Some("caller-owned-task-continuation"));
            assert_eq!(calls.load(Ordering::Acquire), 0);
            assert_eq!(client.next_id, 3);
            client.list_tools(&cx, &cancellation, None).await.unwrap();
            let _peer = serving.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }
}
