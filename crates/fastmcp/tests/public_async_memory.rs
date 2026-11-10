//! Public in-process serving on a caller-owned runtime without a reactor or
//! blocking pool. The modern facade also runs with `--no-default-features`.

// An integration test is its own crate root, so it inherits no attribute from
// the facade's `src/lib.rs` -- which does not raise this either. Proving `Send`
// for the nested `Facade::serve` async block spawned below overflows the default
// limit, and rustc then ABANDONS the proof rather than failing it, leaving the
// future unchecked rather than shown `Send`. See bd-35ktc.
#![recursion_limit = "512"]
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use asupersync::runtime::RuntimeBuilder;
use fastmcp_rust::memory::{MemoryTransport, create_memory_transport_pair_with_capacity};
use fastmcp_rust::{
    Cx, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION_META_KEY, JsonRpcMessage,
    JsonRpcRequest, JsonRpcResponse, JsonValue, McpContext, McpResult, RequestId, TransportError,
    json, modern, tool,
};

#[tool]
async fn memory_echo(ctx: &McpContext, value: String) -> McpResult<String> {
    assert!(ctx.cx().blocking_pool_handle().is_none());
    asupersync::time::sleep(ctx.cx().now(), Duration::from_millis(1)).await;
    ctx.checkpoint()?;
    Ok(value)
}

#[derive(Clone, Copy, Debug)]
enum Facade {
    Modern,
    #[cfg(feature = "legacy-2024-11-05")]
    Auto,
    #[cfg(feature = "legacy-2024-11-05")]
    Legacy,
}

impl Facade {
    async fn serve(
        self,
        cx: &Cx,
        transport: MemoryTransport,
        stopped: Arc<AtomicBool>,
    ) -> McpResult<()> {
        let shutdown = move || stopped.store(true, Ordering::Release);
        match self {
            Self::Modern => {
                modern::ServerBuilder::new("facade-memory", "1.2.3")
                    .tool(MemoryEcho)
                    .on_shutdown(shutdown)
                    .build()
                    .serve_memory(cx, transport)
                    .await
            }
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Auto => {
                fastmcp_rust::auto::ServerBuilder::new("facade-memory", "1.2.3")
                    .tool(MemoryEcho)
                    .on_shutdown(shutdown)
                    .build()
                    .serve_memory(cx, transport)
                    .await
            }
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Legacy => {
                fastmcp_rust::legacy_2024::ServerBuilder::new("facade-memory", "1.2.3")
                    .tool(MemoryEcho)
                    .on_shutdown(shutdown)
                    .build()
                    .serve_memory(cx, transport)
                    .await
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum PeerEra {
    Modern,
    #[cfg(feature = "legacy-2024-11-05")]
    Legacy,
}

impl PeerEra {
    fn request(self, id: i64, method: &str, mut params: JsonValue) -> JsonRpcMessage {
        match self {
            Self::Modern => {
                params["_meta"] = json!({
                    FINAL_PROTOCOL_VERSION_META_KEY: modern::PROTOCOL_VERSION,
                    FINAL_CLIENT_CAPABILITIES_META_KEY: {},
                });
            }
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Legacy => {}
        }
        JsonRpcMessage::Request(JsonRpcRequest::new(method, Some(params), id))
    }

    async fn open(self, cx: &Cx, peer: &mut MemoryTransport) {
        match self {
            Self::Modern => {
                peer.send_async(cx, &self.request(1, "server/discover", json!({})))
                    .await
                    .unwrap();
                let response = response(cx, peer, 1).await;
                assert!(response.error.is_none());
                let result = response.result.unwrap();
                assert_eq!(result["resultType"], "complete");
                assert_eq!(
                    result["supportedVersions"],
                    json!([modern::PROTOCOL_VERSION])
                );
            }
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Legacy => {
                peer.send_async(
                    cx,
                    &self.request(
                        1,
                        "initialize",
                        json!({
                            "protocolVersion": fastmcp_rust::legacy_2024::PROTOCOL_VERSION,
                            "capabilities": {},
                            "clientInfo": {"name": "facade-memory-peer", "version": "1"},
                        }),
                    ),
                )
                .await
                .unwrap();
                let response = response(cx, peer, 1).await;
                assert!(response.error.is_none());
                let result = response.result.unwrap();
                assert_eq!(
                    result["protocolVersion"],
                    fastmcp_rust::legacy_2024::PROTOCOL_VERSION
                );
                assert_eq!(
                    result["serverInfo"],
                    json!({"name": "facade-memory", "version": "1.2.3"})
                );
                assert!(result.get("resultType").is_none());
                peer.send_async(
                    cx,
                    &JsonRpcMessage::Request(JsonRpcRequest::notification(
                        "notifications/initialized",
                        None,
                    )),
                )
                .await
                .unwrap();
            }
        }
    }

    fn assert_echo(self, response: JsonRpcResponse, value: &str) {
        assert!(response.error.is_none(), "{:?}", response.error);
        let result = response.result.unwrap();
        assert_eq!(result["content"], json!([{"type": "text", "text": value}]));
        assert_ne!(result["isError"], true);
        match self {
            Self::Modern => assert_eq!(result["resultType"], "complete"),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Legacy => assert!(result.get("resultType").is_none()),
        }
    }
}

async fn response(cx: &Cx, peer: &mut MemoryTransport, id: i64) -> JsonRpcResponse {
    let JsonRpcMessage::Response(response) = peer.recv_async(cx).await.unwrap() else {
        panic!("expected response to {id}");
    };
    assert_eq!(response.id, Some(RequestId::Number(id)));
    response
}

fn run_facade(facade: Facade, era: PeerEra) {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
            let (mut peer, transport) = create_memory_transport_pair_with_capacity(1);
            let stopped = Arc::new(AtomicBool::new(false));
            let server_stopped = Arc::clone(&stopped);
            let mut serving = cx
                .spawn(move |serve_cx| async move {
                    facade.serve(&serve_cx, transport, server_stopped).await
                })
                .unwrap();
            era.open(&cx, &mut peer).await;

            let value = format!("{facade:?} {era:?} résumé 東京\\literal\nline");
            let params = json!({"name": "memory_echo", "arguments": {"value": value}});
            peer.send_async(&cx, &era.request(2, "tools/call", params.clone()))
                .await
                .unwrap();
            era.assert_echo(response(&cx, &mut peer, 2).await, &value);

            // Change only the method. A refusal must not tear down the era or
            // prevent a later request on this same bounded connection.
            peer.send_async(&cx, &era.request(3, "memory/notRegistered", params.clone()))
                .await
                .unwrap();
            let refused = response(&cx, &mut peer, 3).await;
            assert_eq!(refused.error.unwrap().code.as_i32(), Some(-32601));
            assert!(refused.result.is_none());
            peer.send_async(&cx, &era.request(4, "tools/call", params.clone()))
                .await
                .unwrap();
            era.assert_echo(response(&cx, &mut peer, 4).await, &value);
            assert!(!stopped.load(Ordering::Acquire));

            // Close ingress with accepted work outstanding. The final result
            // must drain before shutdown even with one-slot output capacity.
            peer.send_async(&cx, &era.request(5, "tools/call", params))
                .await
                .unwrap();
            let (mut input, output) = peer.into_split();
            drop(output);
            let JsonRpcMessage::Response(final_response) = input.recv_async(&cx).await.unwrap()
            else {
                panic!("half-close must retain the accepted request's result");
            };
            assert_eq!(final_response.id, Some(RequestId::Number(5)));
            era.assert_echo(final_response, &value);
            assert!(matches!(
                input.recv_async(&cx).await,
                Err(TransportError::Closed)
            ));
            serving.join(&cx).await.unwrap().unwrap();
            assert!(stopped.load(Ordering::Acquire));
            assert!(cx.checkpoint().is_ok());
        })
        .await
        .expect("public memory serving must make bounded caller-runtime progress");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn modern_facade_async_memory_runs_without_reactor_or_blocking_pool() {
    run_facade(Facade::Modern, PeerEra::Modern);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn auto_facade_async_memory_selects_modern() {
    run_facade(Facade::Auto, PeerEra::Modern);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn auto_facade_async_memory_selects_exact_legacy() {
    run_facade(Facade::Auto, PeerEra::Legacy);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn legacy_facade_async_memory_runs_without_reactor_or_blocking_pool() {
    run_facade(Facade::Legacy, PeerEra::Legacy);
}

mod typed_client {
    use super::*;
    use fastmcp_rust::{
        ClientCapabilities, ClientInfo, ContentBlock, CoreResult, FinalCoreResult, McpErrorCode,
        McpRequestCancellation, MemoryRequestEvent, MemoryRequestExecution,
    };

    fn assert_echo(result: CoreResult, expected: &str) {
        let CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) = result else {
            panic!("memory client must retain a typed modern tool result");
        };
        assert!(!result.payload.is_error);
        assert_eq!(result.payload.content.len(), 1);
        assert!(matches!(
            &result.payload.content[0],
            ContentBlock::Text { text, .. } if text == expected
        ));
    }

    async fn finish(
        cx: &Cx,
        client: &mut fastmcp_rust::client::MemoryClient,
        cancellation: &McpRequestCancellation,
        execution: &mut MemoryRequestExecution,
    ) -> CoreResult {
        loop {
            match client
                .next_event(cx, cancellation, execution)
                .await
                .unwrap()
            {
                Some(MemoryRequestEvent::Result(result)) => {
                    assert!(
                        client
                            .next_event(cx, cancellation, execution)
                            .await
                            .unwrap()
                            .is_none()
                    );
                    return *result;
                }
                Some(MemoryRequestEvent::Notification(_)) => {}
                None => panic!("memory execution must publish its result exactly once"),
            }
        }
    }

    fn run(facade: Facade) {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(cx.blocking_pool_handle().is_none());
            asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
                let (transport, server_transport) = create_memory_transport_pair_with_capacity(1);
                let stopped = Arc::new(AtomicBool::new(false));
                let server_stopped = Arc::clone(&stopped);
                let mut serving = cx
                    .spawn(move |serve_cx| async move {
                        facade
                            .serve(&serve_cx, server_transport, server_stopped)
                            .await
                    })
                    .unwrap();
                let mut client: fastmcp_rust::prelude::MemoryClient =
                    modern::MemoryClient::connect(
                        &cx,
                        transport,
                        ClientInfo {
                            name: "public-memory-client".to_owned(),
                            version: "1".to_owned(),
                        },
                        ClientCapabilities::default(),
                    )
                    .await
                    .unwrap();
                assert!(
                    client
                        .server_discovery()
                        .supported_versions()
                        .iter()
                        .any(|version| version == modern::PROTOCOL_VERSION)
                );
                let cancellation = McpRequestCancellation::new();
                let CoreResult::Final(FinalCoreResult::ToolsList {
                    result: catalog, ..
                }) = client.list_tools(&cx, &cancellation, None).await.unwrap()
                else {
                    panic!("memory catalog must retain its typed result and cache metadata");
                };
                assert_eq!(catalog.payload.tools.len(), 1);
                assert_eq!(catalog.payload.tools[0].name, "memory_echo");
                assert_eq!(
                    catalog.payload.tools[0].input_schema["properties"]["value"]["type"],
                    "string"
                );

                // Refusal happens before publication and consumes no ID.
                assert_eq!(
                    client
                        .execute_core(&cx, &cancellation, "tools/call", json!({}))
                        .await
                        .unwrap_err()
                        .code,
                    McpErrorCode::InvalidParams
                );
                let first_value = "first résumé 東京\\literal\nline";
                let second_value = "second independent request";
                let mut first = client
                    .execute_core(
                        &cx,
                        &cancellation,
                        "tools/call",
                        json!({
                            "name": "memory_echo", "arguments": {"value": first_value},
                        }),
                    )
                    .await
                    .unwrap();
                let mut second = client
                    .execute_core(
                        &cx,
                        &cancellation,
                        "tools/call",
                        json!({
                            "name": "memory_echo", "arguments": {"value": second_value},
                        }),
                    )
                    .await
                    .unwrap();
                assert_eq!(first.request_id(), &RequestId::Number(3));
                assert_eq!(second.request_id(), &RequestId::Number(4));
                // Driving the second owner must preserve the first result,
                // including when its response arrives during send admission.
                assert_echo(
                    finish(&cx, &mut client, &cancellation, &mut second).await,
                    second_value,
                );
                assert_echo(
                    finish(&cx, &mut client, &cancellation, &mut first).await,
                    first_value,
                );
                assert_echo(
                    client
                        .call_tool(
                            &cx,
                            &cancellation,
                            "memory_echo",
                            json!({
                                "value": "same connection remains usable",
                            }),
                        )
                        .await
                        .unwrap(),
                    "same connection remains usable",
                );

                assert!(!stopped.load(Ordering::Acquire));
                client.close(&cx).unwrap();
                serving.join(&cx).await.unwrap().unwrap();
                assert!(stopped.load(Ordering::Acquire));
                assert!(cx.checkpoint().is_ok());
            })
            .await
            .expect("typed memory client and server must progress on their caller runtime");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn modern_memory_client_drives_real_server_without_reactor_or_blocking_pool() {
        run(Facade::Modern);
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn modern_memory_client_drives_auto_server_on_one_slot_channels() {
        run(Facade::Auto);
    }
}

mod subscriptions {
    use super::*;
    use std::future::{Future, poll_fn};
    use std::pin::pin;
    use std::task::Poll;

    use fastmcp_rust::{
        ClientInfo, CoreResult, FinalCoreResult, McpError, McpErrorCode,
        McpRequestCancellation, MemorySubscriptionEvent, ServerNotification,
        SubscriptionFilter, resource, serde_json,
    };

    const RESOURCE: &str = "memory://subscriptions/observed";

    #[resource(uri = "memory://subscriptions/observed")]
    async fn memory_observed(ctx: &McpContext) -> McpResult<String> {
        ctx.checkpoint()?;
        Ok("current resource value".to_owned())
    }

    #[tool]
    async fn memory_emit(ctx: &McpContext, category: String) -> McpResult<bool> {
        ctx.checkpoint()?;
        match category.as_str() {
            "resource" => Ok(ctx.notify_resource_updated(RESOURCE)),
            "tools" => Ok(ctx.disable_tool("memory_echo")),
            "restore" => Ok(ctx.enable_tool("memory_echo")),
            _ => Err(McpError::invalid_params("unknown fixture category")),
        }
    }

    async fn emit(cx: &Cx, client: &mut modern::MemoryClient, category: &str) {
        let CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) = client
            .call_tool(
                cx, &McpRequestCancellation::new(), "memory_emit", json!({"category": category}),
            )
            .await
            .unwrap()
        else {
            panic!("publishing a change must not consume a listener's result");
        };
        assert!(!result.payload.is_error);
        assert_eq!(serde_json::to_value(result.payload).unwrap()["content"][0]["text"], "true");
    }

    #[test]
    fn memory_subscriptions_multiplex_real_catalog_and_resource_events_with_owned_teardown() {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
                let server = modern::ServerBuilder::new("memory-subscriptions", "1")
                    .tool(MemoryEcho)
                    .tool(MemoryEmit)
                    .resource(MemoryObservedResource)
                    .build();
                let (transport, peer) = create_memory_transport_pair_with_capacity(1);
                let mut serving = cx
                    .spawn(move |serve_cx| async move { server.serve_memory(&serve_cx, peer).await })
                    .unwrap();
                let mut client = modern::MemoryClient::builder(ClientInfo {
                    name: "memory-subscription-client".to_owned(),
                    version: "1".to_owned(),
                })
                .connect(&cx, transport)
                .await
                .unwrap();
                let cancellation = McpRequestCancellation::new();
                let mut catalog: fastmcp_rust::prelude::MemorySubscriptionExecution = client
                    .subscribe(&cx, &cancellation, SubscriptionFilter {
                        tools_list_changed: Some(true),
                        ..SubscriptionFilter::default()
                    })
                    .await
                    .unwrap();
                let Some(MemorySubscriptionEvent::Acknowledged { accepted, .. }) = client
                    .next_subscription_event(&cx, &cancellation, &mut catalog)
                    .await
                    .unwrap()
                else {
                    panic!("the actual server must acknowledge the catalog listener first");
                };
                assert_eq!(accepted.tools_list_changed, Some(true));
                assert_eq!(catalog.accepted_filter(), Some(accepted));
                let mut resource = client
                    .subscribe(&cx, &cancellation, SubscriptionFilter {
                        resource_subscriptions: Some(vec![RESOURCE.to_owned()]),
                        ..SubscriptionFilter::default()
                    })
                    .await
                    .unwrap();
                assert!(matches!(
                    client.next_subscription_event(&cx, &cancellation, &mut resource).await.unwrap(),
                    Some(MemorySubscriptionEvent::Acknowledged { accepted, .. })
                        if accepted.resource_subscriptions == Some(vec![RESOURCE.to_owned()])
                ));

                // Abandon only a pending event wait, then drive ordinary
                // requests. Both listener owners and their ingress survive.
                {
                    let mut waiting = pin!(client.next_subscription_event(
                        &cx, &cancellation, &mut resource,
                    ));
                    assert!(poll_fn(|task| Poll::Ready(waiting.as_mut().poll(task))).await.is_pending());
                }
                emit(&cx, &mut client, "resource").await;
                emit(&cx, &mut client, "tools").await;
                let Some(MemorySubscriptionEvent::Notification(notification)) = client
                    .next_subscription_event(&cx, &cancellation, &mut catalog)
                    .await
                    .unwrap()
                else {
                    panic!("the catalog owner must retain its notification while calls run");
                };
                assert!(matches!(*notification, ServerNotification::ToolsListChanged(_)));
                assert_eq!(
                    notification.encode().unwrap().params.unwrap()["_meta"]["io.modelcontextprotocol/subscriptionId"],
                    serde_json::to_value(catalog.request_id()).unwrap(),
                );
                let Some(MemorySubscriptionEvent::Notification(notification)) = client
                    .next_subscription_event(&cx, &cancellation, &mut resource)
                    .await
                    .unwrap()
                else {
                    panic!("the resource owner must retain its separate notification");
                };
                assert!(matches!(*notification, ServerNotification::ResourceUpdated(_)));
                let wire = notification.encode().unwrap();
                let params = wire.params.unwrap();
                assert_eq!(params["uri"], RESOURCE);
                assert_eq!(params["_meta"]["io.modelcontextprotocol/subscriptionId"],
                    serde_json::to_value(resource.request_id()).unwrap());
                assert!(client.take_server_notifications().is_empty());

                client.cancel_subscription(&cx, &mut catalog).unwrap();
                assert_eq!(
                    client.next_subscription_event(&cx, &cancellation, &mut catalog)
                        .await.unwrap_err().code,
                    McpErrorCode::RequestCancelled,
                );
                assert!(catalog.terminal_result().is_none());
                emit(&cx, &mut client, "resource").await;
                assert!(matches!(
                    client.next_subscription_event(&cx, &cancellation, &mut resource).await.unwrap(),
                    Some(MemorySubscriptionEvent::Notification(notification))
                        if matches!(*notification, ServerNotification::ResourceUpdated(_))
                ));

                // An empty accepted filter remains a live listener. Local
                // cancellation must not fabricate a successful complete result.
                let mut empty = client
                    .subscribe(&cx, &cancellation, SubscriptionFilter::default())
                    .await
                    .unwrap();
                assert!(matches!(
                    client.next_subscription_event(&cx, &cancellation, &mut empty).await.unwrap(),
                    Some(MemorySubscriptionEvent::Acknowledged { accepted, .. })
                        if accepted == SubscriptionFilter::default()
                ));
                {
                    let mut waiting = pin!(client.next_subscription_event(
                        &cx, &cancellation, &mut empty,
                    ));
                    assert!(poll_fn(|task| Poll::Ready(waiting.as_mut().poll(task))).await.is_pending());
                }
                client.cancel_subscription(&cx, &mut empty).unwrap();
                assert_eq!(
                    client.next_subscription_event(&cx, &cancellation, &mut empty)
                        .await.unwrap_err().code,
                    McpErrorCode::RequestCancelled,
                );
                assert!(empty.terminal_result().is_none());
                assert!(client.next_subscription_event(&cx, &cancellation, &mut empty).await.unwrap().is_none());

                drop(resource);
                emit(&cx, &mut client, "restore").await;
                client.call_tool(&cx, &cancellation, "memory_echo", json!({"value": "listeners retired"})).await.unwrap();
                assert!(client.take_server_notifications().is_empty());
                client.close(&cx).unwrap();
                serving.join(&cx).await.unwrap().unwrap();
                assert!(cx.checkpoint().is_ok());
            })
            .await
            .expect("subscriptions and ordinary work must share bounded Memory transport");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}

mod interactions {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    use fastmcp_rust::{
        ClientCapabilities, ClientInfo, CompleteResult, CoreResult, FinalCoreResult,
        FinalElicitationContextExt, FinalEmbeddedRootsListParams, FinalGetPromptResult,
        FinalReadResourceResult, FinalRootsContextExt, FinalSamplingContextExt,
        FinalToolOutcome, McpError, McpRequestCancellation, MrtrCompletedInputs, ResultMeta,
        prompt, resource, serde_json,
    };
    // The facade scopes these two under `modern::` rather than re-exporting them
    // at the root; the root carries `FinalToolOutcome` but not these. Naming the
    // module the facade actually exposes is the fix, not widening the root.
    use fastmcp_rust::modern::{FinalMethodOutcome, ReverseRequestHandlers};

    // The return type must be WRITTEN as a qualified path.
    // `is_canonical_final_tool_outcome` in fastmcp-macros requires at least two
    // path segments rooted at `fastmcp_rust` or `fastmcp_server`, so a bare
    // `FinalToolOutcome` -- however it was imported -- is refused. The macro
    // matches tokens, not resolved types, and that is deliberate: the generated
    // code must not be able to bind some other same-named type. Same spelling
    // as macro_expansion.rs:1690.
    #[tool]
    async fn memory_interactive_tool(
        ctx: &McpContext,
        subject: String,
        completed_inputs: Option<&MrtrCompletedInputs>,
    ) -> McpResult<fastmcp_rust::FinalToolOutcome> {
        ctx.checkpoint()?;
        let Some(inputs) = completed_inputs else {
            return Ok(FinalToolOutcome::InputRequired(
                ctx.final_sampling(
                    "sample",
                    serde_json::from_value(json!({
                        "messages": [{"role": "user", "content": {
                            "type": "text", "text": subject,
                        }}],
                        "maxTokens": 16,
                    }))
                    .unwrap(),
                )?
                .into_input_required()?,
            ));
        };
        let sample = inputs
            .sampling("sample")?
            .ok_or_else(|| McpError::internal_error("missing admitted sample"))?;
        Ok(FinalToolOutcome::Complete(CompleteResult::new(
            serde_json::from_value(json!({
                "content": [{"type": "text", "text": format!("{subject}:{}", sample.model)}],
                "isError": false,
            }))
            .unwrap(),
            ResultMeta::empty(),
        )))
    }

    #[resource(uri = "memory://interactive/{subject}")]
    async fn memory_interactive_resource(
        ctx: &McpContext,
        subject: String,
        completed_inputs: Option<&MrtrCompletedInputs>,
    ) -> McpResult<FinalMethodOutcome<FinalReadResourceResult>> {
        ctx.checkpoint()?;
        let Some(inputs) = completed_inputs else {
            return Ok(FinalMethodOutcome::InputRequired(
                ctx.final_roots("roots", FinalEmbeddedRootsListParams::default())?
                    .into_input_required()?,
            ));
        };
        let roots = inputs
            .roots("roots")?
            .ok_or_else(|| McpError::internal_error("missing admitted roots"))?;
        Ok(FinalMethodOutcome::Complete(CompleteResult::new(
            serde_json::from_value(json!({
                "contents": [{
                    "uri": format!("memory://interactive/{subject}"),
                    "text": format!("{subject}:{}", roots.roots.len()),
                }],
                "ttlMs": 0,
                "cacheScope": "private",
            }))
            .unwrap(),
            ResultMeta::empty(),
        )))
    }

    #[prompt]
    async fn memory_interactive_prompt(
        ctx: &McpContext,
        subject: String,
        completed_inputs: Option<&MrtrCompletedInputs>,
    ) -> McpResult<FinalMethodOutcome<FinalGetPromptResult>> {
        ctx.checkpoint()?;
        let Some(inputs) = completed_inputs else {
            return Ok(FinalMethodOutcome::InputRequired(
                ctx.final_elicitation_form(
                    "approval",
                    "Approve the memory operation",
                    json!({
                        "type": "object", "properties": {"approved": {"type": "boolean"}},
                        "required": ["approved"],
                    }),
                )?
                .into_input_required()?,
            ));
        };
        let answer = inputs
            .elicitation("approval")?
            .ok_or_else(|| McpError::internal_error("missing admitted approval"))?;
        Ok(FinalMethodOutcome::Complete(CompleteResult::new(
            serde_json::from_value(json!({
                "messages": [{"role": "assistant", "content": {
                    "type": "text", "text": format!(
                        "{subject}:{}", answer.get_bool("approved").unwrap_or(false)
                    ),
                }}],
            }))
            .unwrap(),
            ResultMeta::empty(),
        )))
    }

    fn handlers(calls: &Arc<AtomicUsize>) -> ReverseRequestHandlers {
        let sampling = Arc::clone(calls);
        let roots = Arc::clone(calls);
        let elicitation = Arc::clone(calls);
        let worker = std::thread::current().id();
        ReverseRequestHandlers::new()
            .with_modern_sampling_create_message(move |cx, _, params| {
                let calls = Arc::clone(&sampling);
                Box::pin(async move {
                    assert_eq!(std::thread::current().id(), worker);
                    assert!(cx.blocking_pool_handle().is_none());
                    assert_eq!(serde_json::to_value(params).unwrap()["maxTokens"], 16);
                    calls.fetch_add(1, Ordering::AcqRel);
                    asupersync::runtime::yield_now().await;
                    cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
                    Ok(serde_json::from_value(json!({
                        "role": "assistant", "model": "caller-model",
                        "content": {"type": "text", "text": "sampled résumé"},
                    }))
                    .unwrap())
                })
            })
            .with_modern_roots_list(move |cx, _, _| {
                let calls = Arc::clone(&roots);
                Box::pin(async move {
                    assert_eq!(std::thread::current().id(), worker);
                    assert!(cx.blocking_pool_handle().is_none());
                    calls.fetch_add(1, Ordering::AcqRel);
                    asupersync::runtime::yield_now().await;
                    cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
                    Ok(serde_json::from_value(json!({"roots": []})).unwrap())
                })
            })
            .with_modern_elicitation_create(move |cx, _, _| {
                let calls = Arc::clone(&elicitation);
                Box::pin(async move {
                    assert_eq!(std::thread::current().id(), worker);
                    assert!(cx.blocking_pool_handle().is_none());
                    calls.fetch_add(1, Ordering::AcqRel);
                    asupersync::runtime::yield_now().await;
                    cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
                    Ok(serde_json::from_value(json!({
                        "action": "accept", "content": {"approved": true},
                    }))
                    .unwrap())
                })
            })
    }

    #[test]
    fn memory_interactions_resolve_sampling_roots_and_elicitation_through_the_real_server() {
        for installed in [false, true] {
            let runtime = RuntimeBuilder::current_thread()
                .blocking_threads(0, 0)
                .build()
                .unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
                    let server = modern::ServerBuilder::new("memory-interactions", "1")
                        .tool(MemoryEcho)
                        .tool(MemoryInteractiveTool)
                        .resource(MemoryInteractiveResourceResource)
                        .prompt(MemoryInteractivePromptPrompt)
                        .build();
                    let (transport, peer) = create_memory_transport_pair_with_capacity(1);
                    let mut serving = cx
                        .spawn(move |serve_cx| async move { server.serve_memory(&serve_cx, peer).await })
                        .unwrap();
                    let calls = Arc::new(AtomicUsize::new(0));
                    let capabilities: ClientCapabilities = serde_json::from_value(json!({
                        "sampling": {}, "roots": {}, "elicitation": {"form": {}},
                    }))
                    .unwrap();
                    let builder = modern::MemoryClient::builder(ClientInfo {
                        name: "memory-interactions-client".to_owned(),
                        version: "1".to_owned(),
                    })
                    .capabilities(capabilities);
                    let builder = if installed {
                        builder.reverse_request_handlers(handlers(&calls))
                    } else {
                        builder
                    };
                    let mut client = builder.connect(&cx, transport).await.unwrap();
                    let cancellation = McpRequestCancellation::new();
                    let tool = client
                        .call_tool(
                            &cx, &cancellation, "memory_interactive_tool", json!({"subject": "tool"}),
                        )
                        .await
                        .unwrap();
                    let resource = client
                        .read_resource(&cx, &cancellation, "memory://interactive/resource")
                        .await
                        .unwrap();
                    let prompt = client
                        .get_prompt(
                            &cx, &cancellation, "memory_interactive_prompt",
                            HashMap::from([("subject".to_owned(), "prompt".to_owned())]),
                        )
                        .await
                        .unwrap();
                    if installed {
                        let CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) = tool else {
                            panic!("sampling must complete the original tool invocation");
                        };
                        assert_eq!(serde_json::to_value(result.payload).unwrap()["content"][0]["text"], "tool:caller-model");
                        let CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. }) = resource else {
                            panic!("roots must complete the original resource read");
                        };
                        assert_eq!(serde_json::to_value(result.payload).unwrap()["contents"][0]["text"], "resource:0");
                        let CoreResult::Final(FinalCoreResult::PromptsGet { result, .. }) = prompt else {
                            panic!("elicitation must complete the original prompt invocation");
                        };
                        assert_eq!(serde_json::to_value(result.payload).unwrap()["messages"][0]["content"]["text"], "prompt:true");
                        assert_eq!(calls.load(Ordering::Acquire), 3);
                    } else {
                        for result in [tool, resource, prompt] {
                            let required = match result {
                                CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { result, .. })
                                | CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { result, .. })
                                | CoreResult::Final(FinalCoreResult::PromptsGetInputRequired { result, .. }) => result,
                                _ => panic!("without handlers the typed input-required result remains caller-owned"),
                            };
                            assert!(required.request_state().is_some());
                        }
                        assert_eq!(calls.load(Ordering::Acquire), 0);
                    }
                    client.call_tool(&cx, &cancellation, "memory_echo", json!({"value": "still live"})).await.unwrap();
                    assert!(cx.checkpoint().is_ok());
                    client.close(&cx).unwrap();
                    serving.join(&cx).await.unwrap().unwrap();
                })
                .await
                .expect("all three interaction kinds must progress on their caller runtime");
            });
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }
}

#[cfg(feature = "apps")]
mod apps_resources {
    use super::*;
    use fastmcp_rust::{
        AbsoluteUri, ClientInfo, CoreResult, FinalCoreResult, MCP_APPS_HTML_MIME_TYPE,
        McpAppsClientSettings, McpAppsResourceBinding, McpAppsResourceCsp, McpAppsResourceMetadata,
        McpAppsResourcePermission, McpAppsResourcePermissions, McpRequestCancellation,
    };

    const URI: &str = "ui://memory-app/dashboard";
    const HTML: &str = "<main>résumé 東京 &amp; weather</main>";

    fn read_apps_resource(include_metadata: bool) {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(cx.blocking_pool_handle().is_none());
            asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
                let mut resource = modern::McpAppsUiResource::try_new(
                    AbsoluteUri::parse(URI).unwrap(),
                    "memory-app",
                    HTML,
                )
                .unwrap();
                let expected_metadata = include_metadata.then(|| {
                    McpAppsResourceMetadata::try_new(
                        Some(
                            McpAppsResourceCsp::try_new(
                                Some(vec!["https://api.example.test".to_owned()]),
                                Some(vec!["https://static.example.test".to_owned()]),
                                None,
                                None,
                            )
                            .unwrap(),
                        ),
                        Some(McpAppsResourcePermissions {
                            geolocation: Some(McpAppsResourcePermission::default()),
                            ..McpAppsResourcePermissions::default()
                        }),
                        Some("memory-app.host.example".to_owned()),
                        Some(true),
                    )
                    .unwrap()
                });
                if let Some(metadata) = &expected_metadata {
                    resource = resource.with_apps_metadata(metadata.clone()).unwrap();
                }
                let stopped = Arc::new(AtomicBool::new(false));
                let server_stopped = Arc::clone(&stopped);
                let server = modern::ServerBuilder::new("memory-apps", "1")
                    .mcp_apps()
                    .unwrap()
                    .mcp_apps_ui_resource(resource)
                    .unwrap()
                    .on_shutdown(move || server_stopped.store(true, Ordering::Release))
                    .build();
                let (transport, peer) = create_memory_transport_pair_with_capacity(1);
                let mut serving = cx
                    .spawn(
                        move |serve_cx| async move { server.serve_memory(&serve_cx, peer).await },
                    )
                    .unwrap();
                let mut client = modern::MemoryClient::builder(ClientInfo {
                    name: "public-memory-apps".to_owned(),
                    version: "1".to_owned(),
                })
                .mcp_apps(
                    McpAppsClientSettings::new(vec![MCP_APPS_HTML_MIME_TYPE.to_owned()]).unwrap(),
                )
                .connect(&cx, transport)
                .await
                .unwrap();
                assert!(client.mcp_apps_active());
                let cancellation = McpRequestCancellation::new();

                // A host may load a tool's resourceUri directly. No catalog
                // fetch can stand in for the metadata on the actual content.
                let CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. }) =
                    client.read_resource(&cx, &cancellation, URI).await.unwrap()
                else {
                    panic!("the public Apps read must return typed modern contents");
                };
                let binding = McpAppsResourceBinding {
                    resource_uri: AbsoluteUri::parse(URI).unwrap(),
                    visibility: Vec::new(),
                };
                let admitted: fastmcp_rust::modern::McpAppsResourceRead<'_> =
                    binding.resolve_read_result(&result.payload, None).unwrap();
                assert!(std::ptr::eq(
                    admitted.contents(),
                    &result.payload.contents[0]
                ));
                assert_eq!(admitted.metadata(), expected_metadata.as_ref());
                let contents = serde_json::to_value(&result.payload).unwrap();
                assert_eq!(contents["contents"].as_array().unwrap().len(), 1);
                let content = &contents["contents"][0];
                assert_eq!(content["uri"], URI);
                assert_eq!(content["mimeType"], MCP_APPS_HTML_MIME_TYPE);
                assert_eq!(content["text"], HTML);
                if let Some(metadata) = &expected_metadata {
                    assert_eq!(content["_meta"]["ui"], json!(metadata));
                } else {
                    assert!(content.get("_meta").is_none());
                }

                let CoreResult::Final(FinalCoreResult::ResourcesList { result, .. }) = client
                    .list_resources(
                        &cx,
                        &cancellation,
                        fastmcp_rust::ListResourcesParams::default(),
                    )
                    .await
                    .unwrap()
                else {
                    panic!("the same Apps connection must retain a typed catalog");
                };
                assert_eq!(result.payload.resources.len(), 1);
                assert_eq!(
                    result.payload.resources[0].mcp_apps_metadata().unwrap(),
                    expected_metadata,
                    "catalog and read metadata must describe the same sandbox requests"
                );

                client.close(&cx).unwrap();
                serving.join(&cx).await.unwrap().unwrap();
                assert!(stopped.load(Ordering::Acquire));
                assert!(cx.checkpoint().is_ok());
            })
            .await
            .expect("Apps resource reads must settle on the caller's runtime");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn public_apps_resource_read_retains_sandbox_metadata_before_catalog_discovery() {
        read_apps_resource(true);
    }

    #[test]
    fn public_apps_resource_read_without_metadata_does_not_invent_sandbox_requests() {
        read_apps_resource(false);
    }
}

#[cfg(feature = "tasks")]
mod typed_tasks {
    use super::*;
    use asupersync::Outcome;
    use std::future::Future;
    use std::sync::atomic::AtomicUsize;

    use fastmcp_rust::{
        ApplicationTaskSupervisor, BoxFuture, ClientCapabilities, ClientInfo, Content, ContentBlock,
        CoreResult, FinalCoreResult, FinalTask, FinalTaskCallToolResult, FinalTaskId,
        FinalTaskInputRequests, FinalTaskInputResponses, FinalTaskRuntime, FinalTaskRuntimeConfig,
        FinalTaskSupervisorFuture, FinalTaskSupervisorHandoff, FinalTaskWaitOutcome,
        FinalTaskWaitPolicy, FinalTaskWorkDescriptor, FinalToolCallOutcome, FinalToolOutcome,
        McpError, McpErrorCode, McpOutcome, McpRequestCancellation, MemorySubscriptionEvent,
        SubscriptionFilter, Tool, ToolExecutionMode, ToolHandler, serde_json,
    };

    const TASK_TOOL: &str = "memory-task";

    #[derive(Default)]
    struct Effects {
        created: AtomicUsize,
        resumed: AtomicUsize,
        holding: AtomicUsize,
        cancelled: AtomicUsize,
    }

    struct TaskTool(Arc<Effects>);

    impl ToolHandler for TaskTool {
        fn definition(&self) -> Tool {
            Tool {
                name: TASK_TOOL.to_owned(),
                description: Some("A task driven by the caller's in-process runtime".to_owned()),
                input_schema: json!({
                    "type": "object",
                    "properties": {"mode": {"enum": ["input", "hold"]}},
                    "required": ["mode"],
                }),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _arguments: JsonValue) -> McpResult<Vec<Content>> {
            Err(McpError::invalid_request("This operation requires modern Tasks"))
        }

        fn declares_final_tasks(&self) -> bool {
            true
        }

        fn execution_mode(&self) -> ToolExecutionMode {
            ToolExecutionMode::Async
        }

        fn call_final_outcome(
            &self,
            _ctx: &McpContext,
            arguments: JsonValue,
        ) -> McpResult<FinalToolOutcome> {
            self.0.created.fetch_add(1, Ordering::AcqRel);
            Ok(FinalToolOutcome::CreateTask {
                work_descriptor: FinalTaskWorkDescriptor::new(arguments)?,
                status_message: Some("accepted over memory transport".to_owned()),
            })
        }

        fn call_final_outcome_async_in_request<'a>(
            &'a self,
            ctx: &'a McpContext,
            _request_cx: &'a Cx,
            arguments: JsonValue,
        ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
            Box::pin(async move {
                assert!(ctx.cx().blocking_pool_handle().is_none());
                match self.call_final_outcome(ctx, arguments) {
                    Ok(outcome) => Outcome::Ok(outcome),
                    Err(error) => Outcome::Err(error),
                }
            })
        }
    }

    struct Supervisor(Arc<Effects>);

    impl ApplicationTaskSupervisor for Supervisor {
        fn resume<'a>(
            &'a self,
            cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            Box::pin(async move {
                assert!(cx.blocking_pool_handle().is_none());
                match handoff {
                    FinalTaskSupervisorHandoff::Initial(initial) => {
                        if initial.work_descriptor().as_value()["mode"] == "input" {
                            let requests: FinalTaskInputRequests = serde_json::from_value(json!({
                                "roots": {"method": "roots/list"},
                            }))
                            .unwrap();
                            initial.require_input(requests, None)?;
                        } else {
                            self.0.holding.fetch_add(1, Ordering::AcqRel);
                            loop {
                                if initial.is_cancellation_requested()? {
                                    initial.honor_cancellation(None)?;
                                    self.0.cancelled.fetch_add(1, Ordering::AcqRel);
                                    break;
                                }
                                cx.checkpoint()
                                    .map_err(|_| McpError::request_cancelled())?;
                                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                            }
                        }
                    }
                    FinalTaskSupervisorHandoff::Resumed(accepted) => {
                        assert_eq!(
                            serde_json::to_value(accepted.input_responses()).unwrap(),
                            json!({"roots": {"roots": []}}),
                        );
                        self.0.resumed.fetch_add(1, Ordering::AcqRel);
                        let result: FinalTaskCallToolResult = serde_json::from_value(json!({
                            "content": [{"type": "text", "text": "task résumé 東京"}],
                            "receipt": {"source": "caller runtime", "items": 0},
                        }))
                        .unwrap();
                        accepted.complete_task(result, None)?;
                    }
                }
                Ok(())
            })
        }
    }

    fn run<F: Future<Output = ()>>(test: impl FnOnce(Cx) -> F) {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(8), test(cx))
                .await
                .expect("Tasks must progress on the caller runtime with one-slot channels");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    fn info() -> ClientInfo {
        ClientInfo {
            name: "public-memory-tasks".to_owned(),
            version: "1".to_owned(),
        }
    }

    fn capabilities() -> ClientCapabilities {
        serde_json::from_value(json!({"roots": {}})).unwrap()
    }

    fn task_runtime() -> FinalTaskRuntime {
        FinalTaskRuntime::in_memory(
            FinalTaskRuntimeConfig::new(60_000, Some(5)).unwrap(),
            Arc::new(|_| {}),
        )
    }

    async fn wait_for_task(
        cx: &Cx,
        client: &mut modern::MemoryClient,
        id: &FinalTaskId,
        predicate: impl Fn(&FinalTask) -> bool,
    ) -> FinalTask {
        loop {
            let observed = client
                .get_task_final(cx, &McpRequestCancellation::new(), id.clone())
                .await
                .unwrap();
            assert_eq!(&observed.task.base().task_id, id);
            if predicate(&observed.task) {
                return observed.task;
            }
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
        }
    }

    async fn assert_echo(cx: &Cx, client: &mut modern::MemoryClient) {
        let CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) = client
            .call_tool(
                cx,
                &McpRequestCancellation::new(),
                "memory_echo",
                json!({"value": "independent core request"}),
            )
            .await
            .unwrap()
        else {
            panic!("the core tool must remain usable after Tasks operations");
        };
        assert!(matches!(
            result.payload.content.as_slice(),
            [ContentBlock::Text { text, .. }] if text == "independent core request"
        ));
    }

    #[test]
    fn memory_tasks_create_accept_input_complete_and_cancel_on_the_caller_runtime() {
        run(|cx| async move {
            let effects = Arc::new(Effects::default());
            let tasks = task_runtime();
            let server = modern::ServerBuilder::new("memory-task-server", "1")
                .tool(TaskTool(Arc::clone(&effects)))
                .tool(MemoryEcho)
                .final_tasks(tasks.clone())
                .unwrap()
                .task_supervisor(Arc::new(Supervisor(Arc::clone(&effects))))
                .build();
            let (transport, server_transport) = create_memory_transport_pair_with_capacity(1);
            let mut serving = cx
                .spawn(move |serve_cx| async move {
                    server.serve_memory(&serve_cx, server_transport).await
                })
                .unwrap();
            let mut client = modern::MemoryClient::builder(info())
                .capabilities(capabilities())
                .with_tasks()
                .connect(&cx, transport)
                .await
                .unwrap();
            assert!(client.tasks_active());
            let cancellation = McpRequestCancellation::new();
            let FinalToolCallOutcome::Task(created) = client
                .call_tool_final_outcome(&cx, &cancellation, TASK_TOOL, json!({"mode": "input"}))
                .await
                .unwrap()
            else {
                panic!("explicitly negotiated Tasks must admit task creation");
            };
            let id = created.task.base().task_id.clone();
            let mut handle = client
                .attach_final_task(&cx, &cancellation, id.clone())
                .await
                .unwrap();
            let wait_policy = FinalTaskWaitPolicy::new(
                Duration::from_secs(2),
                256,
                Duration::from_millis(5),
            )
            .unwrap();
            assert_eq!(
                handle
                    .wait_with_memory(&cx, &mut client, &cancellation, wait_policy)
                    .await
                    .unwrap(),
                FinalTaskWaitOutcome::InputRequired,
            );
            let waiting = handle.task().clone();
            let filter: SubscriptionFilter = serde_json::from_value(json!({
                "taskIds": [id.as_str()],
            }))
            .unwrap();
            let mut observation = client.subscribe(&cx, &cancellation, filter).await.unwrap();
            let Some(MemorySubscriptionEvent::Acknowledged { accepted, unsupported }) = client
                .next_subscription_event(&cx, &cancellation, &mut observation)
                .await
                .unwrap()
            else {
                panic!("the real server must acknowledge the exact Task listener");
            };
            assert_eq!(accepted.additional["taskIds"], json!([id.as_str()]));
            assert!(unsupported.additional.is_empty());
            let wrong: FinalTaskInputResponses =
                serde_json::from_value(json!({"different-key": {"roots": []}})).unwrap();
            assert!(
                client
                    .update_task_final(&cx, &cancellation, &waiting, wrong)
                    .await
                    .is_err()
            );
            assert_eq!(effects.resumed.load(Ordering::Acquire), 0);
            assert!(matches!(
                client
                    .get_task_final(&cx, &cancellation, id.clone())
                    .await
                    .unwrap()
                    .task,
                FinalTask::InputRequired { .. }
            ));

            let input: FinalTaskInputResponses =
                serde_json::from_value(json!({"roots": {"roots": []}})).unwrap();
            let before = serde_json::to_value(handle.task()).unwrap();
            handle
                .resume_input_with_memory(&cx, &mut client, &cancellation, input)
                .await
                .unwrap();
            assert_eq!(
                serde_json::to_value(handle.task()).unwrap(),
                before,
                "an update acknowledgement does not manufacture a newer Task snapshot",
            );
            handle
                .poll_with_memory(&cx, &mut client, &cancellation)
                .await
                .unwrap();
            assert_eq!(
                handle
                    .wait_with_memory(&cx, &mut client, &cancellation, wait_policy)
                    .await
                    .unwrap(),
                FinalTaskWaitOutcome::Completed,
            );
            let FinalTask::Completed { result, .. } = handle.task() else {
                unreachable!();
            };
            assert_eq!(
                serde_json::to_value(result).unwrap(),
                json!({
                    "content": [{"type": "text", "text": "task résumé 東京"}],
                    "receipt": {"source": "caller runtime", "items": 0},
                }),
            );
            assert_eq!(effects.resumed.load(Ordering::Acquire), 1);
            loop {
                let Some(MemorySubscriptionEvent::Task(notification)) = client
                    .next_subscription_event(&cx, &cancellation, &mut observation)
                    .await
                    .unwrap()
                else {
                    panic!("an acknowledged Task listener must deliver its state changes");
                };
                assert_eq!(notification.params.task.base().task_id, id);
                if matches!(&notification.params.task, FinalTask::Completed { .. }) {
                    let wire = serde_json::to_value(&notification).unwrap();
                    assert_eq!(
                        wire["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
                        serde_json::to_value(observation.request_id()).unwrap(),
                    );
                    assert_eq!(
                        serde_json::to_value(&notification.params.task).unwrap(),
                        serde_json::to_value(handle.task()).unwrap(),
                        "subscription delivery and authoritative polling must agree",
                    );
                    break;
                }
            }
            client.cancel_subscription(&cx, &mut observation).unwrap();
            assert_eq!(
                client
                    .next_subscription_event(&cx, &cancellation, &mut observation)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::RequestCancelled,
            );
            assert!(observation.terminal_result().is_none());

            let FinalToolCallOutcome::Task(holding) = client
                .call_tool_final_outcome(&cx, &cancellation, TASK_TOOL, json!({"mode": "hold"}))
                .await
                .unwrap()
            else {
                panic!("the second independent operation must create a task");
            };
            let held_id = holding.task.base().task_id.clone();
            // Wait for the worker, so this exercises cooperative cancellation
            // rather than cancellation of a not-yet-delivered handoff.
            while effects.holding.load(Ordering::Acquire) == 0 {
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
            client
                .cancel_task_final(&cx, &cancellation, held_id.clone())
                .await
                .unwrap();
            wait_for_task(&cx, &mut client, &held_id, |task| {
                matches!(task, FinalTask::Cancelled(_))
            })
            .await;
            assert_eq!(effects.created.load(Ordering::Acquire), 2);
            assert_eq!(effects.cancelled.load(Ordering::Acquire), 1);
            assert_echo(&cx, &mut client).await;
            client.close(&cx).unwrap();
            serving.join(&cx).await.unwrap().unwrap();
            assert!(!tasks.is_task_service_ready());
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn memory_tasks_require_opt_in_before_any_application_request() {
        run(|cx| async move {
            let effects = Arc::new(Effects::default());
            let server = modern::ServerBuilder::new("memory-task-server", "1")
                .tool(TaskTool(Arc::clone(&effects)))
                .tool(MemoryEcho)
                .final_tasks(task_runtime())
                .unwrap()
                .task_supervisor(Arc::new(Supervisor(Arc::clone(&effects))))
                .build();
            let (transport, server_transport) = create_memory_transport_pair_with_capacity(1);
            let mut serving = cx
                .spawn(move |serve_cx| async move {
                    server.serve_memory(&serve_cx, server_transport).await
                })
                .unwrap();
            let mut client = modern::MemoryClient::builder(info())
                .capabilities(capabilities())
                .connect(&cx, transport)
                .await
                .unwrap();
            assert!(!client.tasks_active());
            let cancellation = McpRequestCancellation::new();
            assert!(
                client
                    .call_tool_final_outcome(
                        &cx,
                        &cancellation,
                        TASK_TOOL,
                        json!({"mode": "input"}),
                    )
                    .await
                    .is_err()
            );
            assert!(
                client
                    .get_task_final(
                        &cx,
                        &cancellation,
                        FinalTaskId::parse("never-created").unwrap(),
                    )
                    .await
                    .is_err()
            );
            assert_eq!(effects.created.load(Ordering::Acquire), 0);
            let mut echo = client
                .execute_core(
                    &cx,
                    &cancellation,
                    "tools/call",
                    json!({"name": "memory_echo", "arguments": {"value": "no ID consumed"}}),
                )
                .await
                .unwrap();
            assert_eq!(echo.request_id(), &RequestId::Number(2));
            loop {
                match client.next_event(&cx, &cancellation, &mut echo).await.unwrap() {
                    Some(fastmcp_rust::MemoryRequestEvent::Result(_)) => break,
                    Some(fastmcp_rust::MemoryRequestEvent::Notification(_)) => {}
                    None => panic!("the surviving core request must complete"),
                }
            }
            assert_echo(&cx, &mut client).await;
            client.close(&cx).unwrap();
            serving.join(&cx).await.unwrap().unwrap();
        });
    }
}

mod ordinary_task_boundary {
    use super::*;
    use fastmcp_rust::{
        ClientInfo, CoreResult, FinalCoreResult, McpErrorCode, McpRequestCancellation,
        MemoryRequestEvent,
    };

    const TASKS: &str = "io.modelcontextprotocol/tasks";

    fn reply(id: i64, result: JsonValue) -> JsonRpcMessage {
        JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), result))
    }

    async fn request(cx: &Cx, peer: &mut MemoryTransport, method: &str) -> JsonRpcRequest {
        let JsonRpcMessage::Request(request) = peer.recv_async(cx).await.unwrap() else {
            panic!("the memory client must publish a request");
        };
        assert_eq!(request.method, method);
        request
    }

    fn run(opt_in: bool) {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
                let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
                peer.send_async(
                    &cx,
                    &reply(1, json!({
                        "resultType": "complete", "supportedVersions": [modern::PROTOCOL_VERSION],
                        "capabilities": {"extensions": {TASKS: {}}},
                        "ttlMs": 0, "cacheScope": "private",
                    })),
                )
                .await
                .unwrap();
                let builder = modern::MemoryClient::builder(ClientInfo {
                    name: "ordinary-memory-client".to_owned(),
                    version: "1".to_owned(),
                });
                #[cfg(feature = "tasks")]
                let builder = if opt_in { builder.with_tasks() } else { builder };
                #[cfg(not(feature = "tasks"))]
                assert!(!opt_in);
                let mut client = builder.connect(&cx, transport).await.unwrap();
                request(&cx, &mut peer, "server/discover").await;
                let cancellation = McpRequestCancellation::new();
                let mut ordinary = client
                    .execute_core(
                        &cx,
                        &cancellation,
                        "tools/call",
                        json!({
                            "name": "untrusted-tool", "arguments": {},
                            "_meta": {FINAL_CLIENT_CAPABILITIES_META_KEY: {"extensions": {TASKS: {}}}},
                        }),
                    )
                    .await
                    .unwrap();
                let sent = request(&cx, &mut peer, "tools/call").await;
                assert_eq!(sent.id, Some(RequestId::Number(2)));
                assert!(
                    sent.params.unwrap()["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"]
                        .get(TASKS)
                        .is_none(),
                    "caller metadata and a client opt-in cannot authorize an ordinary request"
                );
                let mut sibling = client
                    .execute_core(&cx, &cancellation, "tools/list", json!({}))
                    .await
                    .unwrap();
                assert_eq!(request(&cx, &mut peer, "tools/list").await.id, Some(RequestId::Number(3)));
                peer.send_async(
                    &cx,
                    &reply(2, json!({
                        "resultType": "task",
                        "taskId": "unsolicited-task", "status": "working", "ttlMs": 60_000,
                        "createdAt": "2026-07-28T12:00:00.000Z",
                        "lastUpdatedAt": "2026-07-28T12:00:00.000Z",
                    })),
                )
                .await
                .unwrap();
                let refused = client
                    .next_event(&cx, &cancellation, &mut ordinary)
                    .await
                    .expect_err("a well-shaped unsolicited Task must fail its ordinary owner");
                assert_eq!(refused.code, McpErrorCode::InvalidRequest);
                peer.send_async(
                    &cx,
                    &reply(3, json!({
                        "resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private",
                    })),
                )
                .await
                .unwrap();
                let Some(MemoryRequestEvent::Result(result)) = client
                    .next_event(&cx, &cancellation, &mut sibling)
                    .await
                    .unwrap()
                else {
                    panic!("an unrelated request must survive an unsolicited Task result");
                };
                assert!(matches!(*result, CoreResult::Final(FinalCoreResult::ToolsList { .. })));
                assert!(cx.checkpoint().is_ok());
                client.close(&cx).unwrap();
            })
            .await
            .expect("Task refusal must not stall a bounded memory connection");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn ordinary_memory_requests_reject_unsolicited_tasks_in_every_feature_profile() {
        run(false);
    }

    #[cfg(feature = "tasks")]
    #[test]
    fn opted_in_memory_clients_do_not_grant_tasks_to_ordinary_requests() {
        run(true);
    }
}

#[cfg(feature = "tasks")]
mod retention_administration {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::time::Instant;

    use fastmcp_rust::{
        AuthContext, FinalTask, FinalTaskRetentionAuthority, FinalTaskRuntime,
        FinalTaskRuntimeConfig, FinalTaskStatusNotification, FinalTaskStatusNotificationParams,
        FinalTaskStore, InMemoryFinalTaskStore, TaskRetentionAdministrator,
        TaskRetentionAuthorization, TaskRetentionPolicy, TaskRetentionReason,
        TaskRetentionReclamation,
    };

    struct Operator {
        enabled: AtomicBool,
    }

    impl TaskRetentionAdministrator for Operator {
        fn authorize(
            &self,
            ctx: &McpContext,
            _action: &TaskRetentionAuthorization<'_>,
        ) -> McpResult<()> {
            if self.enabled.load(Ordering::Acquire)
                && ctx.auth().is_some_and(|auth| {
                    auth.scopes
                        .iter()
                        .any(|scope| scope == "tasks:retention:admin")
                })
            {
                Ok(())
            } else {
                Err(fastmcp_rust::McpError::invalid_request(
                    "operator permission denied",
                ))
            }
        }
    }

    impl FinalTaskRetentionAuthority for Operator {
        fn authorize_unlimited_retention(&self) -> McpResult<()> {
            Ok(())
        }
    }

    fn retained_task(id: &str, text: &str) -> FinalTask {
        fastmcp_rust::serde_json::from_value(json!({
            "taskId": id,
            "status": "completed",
            "createdAt": "2026-07-28T12:00:00.000Z",
            "lastUpdatedAt": "2026-07-28T12:00:00.001Z",
            "ttlMs": null,
            "result": {"content": [{"type": "text", "text": text}]},
        }))
        .unwrap()
    }

    fn retain(store: &InMemoryFinalTaskStore, task: FinalTask) -> McpResult<()> {
        let notification = FinalTaskStatusNotification::new(FinalTaskStatusNotificationParams {
            task: task.clone(),
            meta: None,
            // Written out rather than imported. `clippy::default_trait_access`
            // wants the concrete type named, but `BTreeMap` is not in scope
            // here and the only use site is inside
            // `#[cfg(feature = "tasks")] mod retention_administration`, so a
            // top-level `use` would be an unused import whenever that feature
            // is off -- which this target is built without.
            additional: std::collections::BTreeMap::default(),
        });
        store.create_task(task, notification)
    }

    #[test]
    fn facade_task_retention_reclaims_capacity_only_under_current_admin_authority() {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let now = Instant::now();
            let elapsed = Arc::new(AtomicU64::new(0));
            let clock = Arc::clone(&elapsed);
            let store = Arc::new(
                InMemoryFinalTaskStore::with_clock(
                    1,
                    Arc::new(move || now + Duration::from_millis(clock.load(Ordering::Acquire))),
                )
                .unwrap()
                .with_retention_policy(
                    TaskRetentionPolicy::new(1, 4096, Duration::from_secs(1)).unwrap(),
                )
                .unwrap(),
            );
            let operator = Arc::new(Operator {
                enabled: AtomicBool::new(true),
            });
            let tasks = FinalTaskRuntime::new(
                store.clone(),
                FinalTaskRuntimeConfig::with_unlimited_ttl(operator.as_ref(), None).unwrap(),
                Arc::new(|_| {}),
            );
            // This fixture installs a retained terminal record through the
            // public trusted-backend API, then uses only facade administration.
            let first = retained_task("retained-terminal", "private retained result");
            let id = first.base().task_id.clone();
            retain(store.as_ref(), first).unwrap();
            let bytes = store.retained_payload_bytes();
            assert!(bytes > 0);
            assert!(retain(store.as_ref(), retained_task("capacity-probe", "blocked")).is_err());

            let mut admin_auth = AuthContext::with_subject("operator");
            admin_auth.scopes.push("tasks:retention:admin".to_owned());
            let admin = McpContext::new(cx.clone(), 1).with_auth(admin_auth);
            let owner =
                McpContext::new(cx.clone(), 2).with_auth(AuthContext::with_subject("task-owner"));
            assert!(tasks.inspect_task_retention(&admin, &id).is_err());
            tasks
                .install_retention_administrator(&cx, operator.clone())
                .unwrap();
            assert!(tasks.inspect_task_retention(&owner, &id).is_err());
            assert_eq!(store.retained_payload_bytes(), bytes);

            let target = tasks.inspect_task_retention(&admin, &id).unwrap();
            let cloned_runtime = tasks.clone();
            assert!(
                cloned_runtime
                    .reclaim_task_retention(&owner, &target, TaskRetentionReason::OperatorRequest,)
                    .is_err()
            );
            operator.enabled.store(false, Ordering::Release);
            assert!(
                cloned_runtime
                    .reclaim_task_retention(&admin, &target, TaskRetentionReason::OperatorRequest,)
                    .is_err()
            );
            assert_eq!(store.retained_payload_bytes(), bytes);
            assert!(store.get_task(&id).unwrap().is_some());

            operator.enabled.store(true, Ordering::Release);
            let TaskRetentionReclamation::Reclaimed(receipt) = cloned_runtime
                .reclaim_task_retention(&admin, &target, TaskRetentionReason::OperatorRequest)
                .unwrap()
            else {
                panic!("the authorized current generation must reclaim")
            };
            assert_eq!(receipt.released_payload_bytes(), bytes);
            assert_eq!(store.retained_payload_bytes(), 0);
            assert!(store.get_task(&id).unwrap().is_none());
            assert_eq!(
                tasks
                    .reclaim_task_retention(&admin, &target, TaskRetentionReason::OperatorRequest,)
                    .unwrap(),
                TaskRetentionReclamation::AlreadyReclaimed(receipt.clone())
            );
            assert!(tasks.task_retention_audit(&owner, None, 1).is_err());
            let audit = tasks.task_retention_audit(&admin, None, 1).unwrap();
            assert_eq!(audit.records(), std::slice::from_ref(&receipt));
            assert_eq!(audit.retained_records(), 1);
            assert!(audit.retained_bytes() <= 4096);

            // Reuse the freed capacity and even the same public identifier.
            // A retained old target must never erase this later generation.
            retain(
                store.as_ref(),
                retained_task("retained-terminal", "successor result"),
            )
            .unwrap();
            let successor = tasks.inspect_task_retention(&admin, &id).unwrap();
            assert!(successor.generation() > target.generation());
            let successor_bytes = store.retained_payload_bytes();
            assert!(
                tasks
                    .reclaim_task_retention(
                        &admin,
                        &successor,
                        TaskRetentionReason::RetentionPolicy,
                    )
                    .is_err(),
                "audit capacity must refuse before releasing the record"
            );
            assert_eq!(store.retained_payload_bytes(), successor_bytes);
            assert!(store.get_task(&id).unwrap().is_some());
            let old_retry = tasks
                .reclaim_task_retention(&admin, &target, TaskRetentionReason::OperatorRequest)
                .unwrap();
            assert!(!matches!(old_retry, TaskRetentionReclamation::Reclaimed(_)));
            assert_eq!(store.retained_payload_bytes(), successor_bytes);

            elapsed.store(1001, Ordering::Release);
            assert_eq!(
                tasks
                    .reclaim_task_retention(&admin, &target, TaskRetentionReason::OperatorRequest,)
                    .unwrap(),
                TaskRetentionReclamation::NotCurrent
            );
            assert_eq!(store.retained_payload_bytes(), successor_bytes);
            let TaskRetentionReclamation::Reclaimed(next_receipt) = tasks
                .reclaim_task_retention(&admin, &successor, TaskRetentionReason::RetentionPolicy)
                .unwrap()
            else {
                panic!("expired audit capacity is reusable")
            };
            assert!(next_receipt.sequence() > receipt.sequence());
            assert_eq!(store.retained_payload_bytes(), 0);
            assert!(cx.checkpoint().is_ok());
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}
