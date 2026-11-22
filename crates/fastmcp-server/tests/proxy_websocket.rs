//! Native WebSocket upstreams exercised through the public typed proxy gateway.
//!
//! These regressions cover the opt-in core proxy and catalog subscription
//! surfaces, not Tasks relay or standards-track WebSocket conformance.

#![cfg(all(feature = "proxy", feature = "websocket"))]
#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::task::Poll;
use std::time::Duration;

use asupersync::net::TcpStream;
use asupersync::runtime::{RuntimeBuilder, TaskHandle, reactor::create_reactor};
use asupersync::sync::Notify;
use asupersync::types::CancelKind;
use asupersync::{Cx, Outcome};
use fastmcp_client::{
    ClientBuilder, ClientProtocolPlan, StdioSubscriptionEvent, SubscriptionTimeoutPolicy,
    WebSocketClient,
};
use fastmcp_core::{
    ClientCapabilityInfo, McpContext, McpError, McpErrorCode, McpLogLevel, McpOutcome,
    McpRequestCancellation, McpResult, NotificationSender, ProgressReporter,
};
use fastmcp_protocol::protocol_policy::{ProtocolEra, ProtocolPolicy};
use fastmcp_protocol::{
    CompleteResult, CompletionValues, Content, FINAL_CLIENT_CAPABILITIES_META_KEY,
    FINAL_LOG_LEVEL_META_KEY, FINAL_PROTOCOL_VERSION, FINAL_PROTOCOL_VERSION_META_KEY,
    FINAL_SUBSCRIPTION_ID_META_KEY, FinalCompletionParams, FinalCompletionValues, JsonRpcMessage,
    JsonRpcRequest, JsonRpcResponse, LegacyCompletionParams, Prompt, PromptArgument, PromptMessage,
    Resource, ResourceContent, ResourceTemplate, ResultMeta, Role, ServerNotification,
    SubscriptionFilter, Tool,
};
use fastmcp_server::{
    BoxFuture, CompletionHandler, FinalToolOutcome, InboundRequestContext, InboundRequestTransport,
    Middleware, ModernConnection, PromptHandler, ProxyClient, ProxyUpstreamAdapter,
    ResourceHandler, Server, ToolExecutionMode, ToolHandler, WebSocketServerShutdown,
};
use fastmcp_transport::websocket::{
    AsyncWsClientTransport, AsyncWsServerTransport, WebSocketListener,
};
use serde_json::{Value, json};

const BOUND: Duration = Duration::from_secs(15);
const RESOURCE: &str = "memo://websocket/upstream";
const TEMPLATE: &str = "memo://websocket/items/{name}";
const EXACT_INTEGER: &str = "922337203685477580812345678901234567890";
const EXACT_DECIMAL: &str = "1.2300e+42";

#[derive(Default)]
struct Effects {
    calls: AtomicUsize,
    reads: AtomicUsize,
    prompts: AtomicUsize,
    completions: AtomicUsize,
    held_dropped: AtomicUsize,
    changed: Notify,
}

struct Held<'a>(&'a Effects);

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.0.held_dropped.fetch_add(1, Ordering::AcqRel);
        self.0.changed.notify_waiters();
    }
}

struct Echo(Arc<Effects>);

impl ToolHandler for Echo {
    fn definition(&self) -> Tool {
        Tool {
            name: "echo".to_owned(),
            description: Some("Native WebSocket proxy fixture".to_owned()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "value": {"type": "string"},
                    "hold": {"type": "boolean"},
                    "toolError": {"type": "boolean"},
                },
                "additionalProperties": false,
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn execution_mode(&self) -> ToolExecutionMode {
        ToolExecutionMode::Async
    }

    fn call(&self, ctx: &McpContext, arguments: Value) -> McpResult<Vec<Content>> {
        ctx.ensure_live()?;
        self.0.calls.fetch_add(1, Ordering::AcqRel);
        Ok(vec![Content::text(
            arguments["value"].as_str().unwrap_or("echo"),
        )])
    }

    fn call_final_outcome_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: Value,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        Box::pin(async move {
            self.0.calls.fetch_add(1, Ordering::AcqRel);
            self.0.changed.notify_waiters();
            if arguments["hold"] == true {
                let _held = Held(&self.0);
                ctx.report_progress_exact(
                    serde_json::from_str(EXACT_INTEGER).unwrap(),
                    None,
                    Some("upstream is waiting"),
                );
                // The proxy must deliver progress before the final response.
                // The downstream progress callback cancels this very request.
                ctx.request_cancelled().await;
                return Outcome::Err(McpError::request_cancelled());
            }
            let payload = serde_json::from_value(json!({
                "content": [{"type": "text", "text": arguments["value"].as_str().unwrap_or("echo")}],
                "structuredContent": {"echo": arguments["value"]},
                "isError": arguments["toolError"] == true,
            }))
            .unwrap();
            Outcome::Ok(FinalToolOutcome::Complete(CompleteResult::new(
                payload,
                ResultMeta::empty(),
            )))
        })
    }
}

struct Note(Arc<Effects>);

impl ResourceHandler for Note {
    fn definition(&self) -> Resource {
        Resource {
            uri: RESOURCE.to_owned(),
            name: "note".to_owned(),
            description: None,
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        ctx.ensure_live()?;
        self.0.reads.fetch_add(1, Ordering::AcqRel);
        Ok(vec![ResourceContent {
            uri: RESOURCE.to_owned(),
            mime_type: Some("text/plain".to_owned()),
            text: Some("upstream note: 世界 + %2F".to_owned()),
            blob: None,
        }])
    }
}

struct Welcome(Arc<Effects>);

impl PromptHandler for Welcome {
    fn definition(&self) -> Prompt {
        Prompt {
            name: "welcome".to_owned(),
            description: None,
            arguments: vec![PromptArgument {
                name: "name".to_owned(),
                description: None,
                required: true,
            }],
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn get(
        &self,
        ctx: &McpContext,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        ctx.ensure_live()?;
        self.0.prompts.fetch_add(1, Ordering::AcqRel);
        Ok(vec![PromptMessage {
            role: Role::User,
            content: Content::text(format!("Welcome, {}", arguments["name"])),
        }])
    }
}

struct Completion(Arc<Effects>);

impl CompletionHandler for Completion {
    fn complete_legacy(
        &self,
        _: &McpContext,
        _: LegacyCompletionParams,
    ) -> McpResult<CompletionValues> {
        Err(McpError::invalid_request(
            "fixture completion is modern-only",
        ))
    }

    fn complete_final(
        &self,
        ctx: &McpContext,
        params: FinalCompletionParams,
    ) -> McpResult<FinalCompletionValues> {
        ctx.ensure_live()?;
        let reference = serde_json::to_value(&params.reference).unwrap();
        assert_eq!(
            reference["name"], "welcome",
            "gateway removes its own prefix"
        );
        assert_eq!(params.argument.name, "name");
        self.0.completions.fetch_add(1, Ordering::AcqRel);
        Ok(FinalCompletionValues {
            values: vec![format!("{}-complete", params.argument.value)],
            total: Some(serde_json::from_str(EXACT_INTEGER).unwrap()),
            has_more: Some(false),
        })
    }
}

struct OpaqueResult;

impl Middleware for OpaqueResult {
    fn on_response(
        &self,
        _: &McpContext,
        request: &JsonRpcRequest,
        mut result: Value,
    ) -> McpResult<Value> {
        if result["resultType"] == "complete" {
            result["vendorExact"] = serde_json::from_str(EXACT_INTEGER).unwrap();
            result["vendorDecimal"] = serde_json::from_str(EXACT_DECIMAL).unwrap();
            result["vendorHints"] = json!({"nextCursor": "inert", "ttlMs": 999});
            if !result["_meta"].is_object() {
                result["_meta"] = json!({});
            }
            result["_meta"]["com.example/upstream-method"] = json!(request.method);
        }
        Ok(result)
    }
}

fn upstream(effects: &Arc<Effects>, policy: ProtocolPolicy) -> Server {
    Server::new("native-websocket-upstream", "1")
        .protocol_policy(policy)
        .unwrap()
        .tool(Echo(Arc::clone(effects)))
        .resource(Note(Arc::clone(effects)))
        .resource_template(ResourceTemplate {
            uri_template: TEMPLATE.to_owned(),
            name: "notes".to_owned(),
            description: None,
            mime_type: Some("text/plain".to_owned()),
            icon: None,
            version: None,
            tags: Vec::new(),
        })
        .prompt(Welcome(Arc::clone(effects)))
        .completion_handler(Completion(Arc::clone(effects)))
        .middleware(OpaqueResult)
        .build()
}

struct Running {
    address: SocketAddr,
    owner: Cx,
    task: Option<TaskHandle<McpResult<WebSocketServerShutdown>>>,
}

impl Running {
    async fn start(cx: &Cx, server: Server) -> Self {
        let listener = Box::pin(server.bind_websocket(cx, "127.0.0.1:0"))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (ready, mut readiness) = asupersync::channel::oneshot::channel();
        let task = cx
            .spawn(move |server_cx| async move {
                let _ = ready.send_blocking(server_cx.clone());
                Box::pin(listener.serve(&server_cx)).await
            })
            .unwrap();
        let owner = readiness.recv(cx).await.unwrap();
        Self {
            address,
            owner,
            task: Some(task),
        }
    }

    async fn stop(mut self, cx: &Cx) {
        self.owner
            .cancel_with(CancelKind::User, Some("WebSocket proxy test complete"));
        asupersync::time::timeout(cx.now(), BOUND, async {
            let shutdown = self.task.as_mut().unwrap().join(cx).await.unwrap().unwrap();
            self.task = None;
            if let WebSocketServerShutdown::Nonquiescent(shutdown) = shutdown {
                shutdown.settle(cx).await.unwrap();
            }
        })
        .await
        .expect("native listener and connection children settle within the bound");
        assert!(
            cx.checkpoint().is_ok(),
            "listener shutdown is not caller cancellation"
        );
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.owner
            .cancel_with(CancelKind::User, Some("WebSocket proxy test owner dropped"));
    }
}

fn run<F, Fut>(scenario: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    assert!(runtime.blocking_handle().is_none());
    runtime.block_on(async {
        let parent = Cx::current().unwrap();
        let mut task = parent
            .spawn(move |cx| async move {
                asupersync::time::timeout(cx.now(), BOUND, scenario(cx))
                    .await
                    .expect("native proxy exchange finishes without a blocking worker");
            })
            .unwrap();
        task.join(&parent).await.unwrap();
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
}

async fn client(
    cx: &Cx,
    address: SocketAddr,
    policy: ProtocolPolicy,
) -> WebSocketClient<TcpStream> {
    let transport = AsyncWsClientTransport::connect(cx, &format!("ws://{address}/mcp"))
        .await
        .unwrap();
    ClientBuilder::new()
        .client_info("configured-proxy-upstream-client", "7")
        .protocol_plan(ClientProtocolPlan::websocket(policy))
        .connect_websocket_with_cx(cx, transport)
        .await
        .unwrap()
}

async fn connect(cx: &Cx, address: SocketAddr, generation: u64) -> ProxyClient {
    let proxy = ProxyClient::from_websocket(
        client(cx, address, ProtocolPolicy::ModernOnly).await,
        generation,
    )
    .unwrap();
    let binding = proxy.upstream_binding().unwrap();
    assert_eq!(binding.era(), ProtocolEra::Modern2026);
    assert_eq!(binding.adapter(), ProxyUpstreamAdapter::ModernWebSocket);
    assert_eq!(binding.configuration_generation(), generation);
    proxy
}

async fn scripted_upstream(
    cx: &Cx,
    listener: &WebSocketListener,
) -> AsyncWsServerTransport<TcpStream> {
    let upgrade = listener.accept(cx).await.unwrap();
    assert_eq!(upgrade.path(), "/mcp");
    let mut peer = upgrade
        .into_admission()
        .unwrap()
        .complete(cx)
        .await
        .unwrap();
    let discovery = upstream_request(&mut peer, cx, "server/discover").await;
    peer.send(
        cx,
        &JsonRpcMessage::Response(JsonRpcResponse::success(
            discovery.id.unwrap(),
            json!({
                "resultType": "complete", "supportedVersions": [FINAL_PROTOCOL_VERSION],
                "capabilities": {"tools": {}}, "ttlMs": 0, "cacheScope": "public",
            }),
        )),
    )
    .await
    .unwrap();
    peer
}

async fn upstream_request(
    peer: &mut AsyncWsServerTransport<TcpStream>,
    cx: &Cx,
    method: &str,
) -> JsonRpcRequest {
    let JsonRpcMessage::Request(request) = peer.recv(cx).await.unwrap() else {
        panic!("expected upstream {method} request");
    };
    assert_eq!(request.method, method);
    assert!(request.id.is_some());
    request
}

async fn dispatch(
    gateway: &Server,
    cx: &Cx,
    id: u64,
    method: &str,
    mut params: Value,
) -> JsonRpcResponse {
    params["_meta"] = json!({
        FINAL_PROTOCOL_VERSION_META_KEY: FINAL_PROTOCOL_VERSION,
        FINAL_CLIENT_CAPABILITIES_META_KEY: {},
        "io.modelcontextprotocol/clientInfo": {"name": "downstream-only", "version": "2"},
    });
    let request = JsonRpcRequest::new(method, Some(params), i64::try_from(id).unwrap());
    let connection = ModernConnection::new();
    let inbound = InboundRequestContext::with_modern_connection(
        cx.clone(),
        id,
        InboundRequestTransport::Memory,
        &connection,
    );
    Box::pin(gateway.dispatch_stateless(&inbound, &request))
        .await
        .expect("a gateway request receives a response")
}

async fn dispatch_on_connection(
    gateway: &Server,
    connection: &ModernConnection,
    cx: &Cx,
    id: u64,
    mut params: Value,
) -> JsonRpcResponse {
    params["_meta"] = json!({
        FINAL_PROTOCOL_VERSION_META_KEY: FINAL_PROTOCOL_VERSION,
        FINAL_CLIENT_CAPABILITIES_META_KEY: {"roots": {}},
        "io.modelcontextprotocol/clientInfo": {"name": "downstream-mrtr", "version": "1"},
    });
    let request = JsonRpcRequest::new("tools/call", Some(params), i64::try_from(id).unwrap());
    let inbound = InboundRequestContext::with_modern_connection(
        cx.clone(),
        id,
        InboundRequestTransport::Memory,
        connection,
    );
    Box::pin(gateway.dispatch_stateless(&inbound, &request))
        .await
        .expect("durable downstream request receives a response")
}

fn complete(response: JsonRpcResponse, method: &str) -> Value {
    assert!(
        response.error.is_none(),
        "gateway {method} failed: {:?}",
        response.error
    );
    let result = response.result.unwrap();
    assert_eq!(result["resultType"], "complete");
    result
}

fn assert_opaque(result: &Value, method: &str) {
    assert_eq!(result["vendorExact"].to_string(), EXACT_INTEGER);
    assert_eq!(result["vendorDecimal"].to_string(), EXACT_DECIMAL);
    assert_eq!(
        result["vendorHints"],
        json!({"nextCursor": "inert", "ttlMs": 999})
    );
    assert_eq!(result["_meta"]["com.example/upstream-method"], method);
}

#[test]
fn native_websocket_proxy_relays_catalog_and_resource_events_without_blocking_calls() {
    run(|cx| async move {
        let effects = Arc::new(Effects::default());
        let server = upstream(&effects, ProtocolPolicy::ModernOnly);
        let publisher = server.subscription_publisher();
        let running = Running::start(&cx, server).await;
        let proxy = connect(&cx, running.address, 41).await;
        let catalog = proxy.catalog_typed_with_cx(&cx).await.unwrap();
        let gateway = Server::new("websocket-subscription-gateway", "1")
            .protocol_policy(ProtocolPolicy::ModernOnly)
            .unwrap()
            .as_proxy_typed("ws", proxy, catalog)
            .unwrap()
            .build();
        let gateway = Running::start(&cx, gateway).await;
        let mut downstream = client(&cx, gateway.address, ProtocolPolicy::ModernOnly).await;
        let filter = SubscriptionFilter {
            tools_list_changed: Some(true),
            resources_list_changed: Some(true),
            prompts_list_changed: Some(true),
            resource_subscriptions: Some(vec![RESOURCE.to_owned()]),
            ..Default::default()
        };
        let cancellation = McpRequestCancellation::new();
        downstream
            .open_subscriptions_listener(&cx, filter.clone())
            .await
            .unwrap();
        match downstream
            .next_subscription_event(&cx, &cancellation)
            .await
            .unwrap()
        {
            StdioSubscriptionEvent::Acknowledged(accepted) => assert_eq!(accepted, filter),
            event => {
                panic!("the upstream must accept the complete filter before events: {event:?}")
            }
        }

        // A pending downstream receive owns no additional listener. Dropping
        // that wait preserves the route while the gateway is still waiting
        // on its silent upstream subscription.
        let mut pending = Box::pin(downstream.next_subscription_event(&cx, &cancellation));
        let first_poll =
            std::future::poll_fn(|task| Poll::Ready(pending.as_mut().poll(task))).await;
        assert!(first_poll.is_pending());
        drop(pending);

        let called = downstream
            .call_tool(
                &cx,
                "ws/echo",
                json!({"value": "call while listener is idle"}),
            )
            .await
            .unwrap();
        let called: Value = serde_json::from_str(&called.encode().unwrap()).unwrap();
        assert_eq!(called["content"][0]["text"], "call while listener is idle");

        for notification in [
            ServerNotification::ToolsListChanged(None),
            ServerNotification::ResourcesListChanged(None),
            ServerNotification::PromptsListChanged(None),
            ServerNotification::ResourceUpdated(
                serde_json::from_value(json!({"uri": RESOURCE})).unwrap(),
            ),
        ] {
            assert_eq!(publisher.publish(notification).unwrap(), 1);
        }
        for method in [
            "notifications/tools/list_changed",
            "notifications/resources/list_changed",
            "notifications/prompts/list_changed",
            "notifications/resources/updated",
        ] {
            let StdioSubscriptionEvent::Notification(notification) = downstream
                .next_subscription_event(&cx, &cancellation)
                .await
                .unwrap()
            else {
                panic!("each published change must cross the native proxy stream");
            };
            let wire = notification.encode().unwrap();
            assert_eq!(wire.method, method);
            let parameters = wire.params.unwrap();
            // Discovery consumed downstream ID 1; the upstream additionally
            // collected four catalogs before opening its own listen request.
            assert_eq!(parameters["_meta"][FINAL_SUBSCRIPTION_ID_META_KEY], 2);
            if method == "notifications/resources/updated" {
                assert_eq!(parameters["uri"], RESOURCE);
            }
        }

        cancellation.cancel();
        assert_eq!(
            downstream
                .next_subscription_event(&cx, &cancellation)
                .await
                .unwrap_err()
                .code,
            McpErrorCode::RequestCancelled,
        );
        let reused = downstream
            .call_tool(
                &cx,
                "ws/echo",
                json!({"value": "after listener cancellation"}),
            )
            .await
            .unwrap();
        let reused: Value = serde_json::from_str(&reused.encode().unwrap()).unwrap();
        assert_eq!(reused["content"][0]["text"], "after listener cancellation");

        // Completing a subsequent native request settles the abandoned
        // listener, so its capacity is available to a fresh owner.
        let replacement = McpRequestCancellation::new();
        downstream
            .open_subscriptions_listener(&cx, filter.clone())
            .await
            .unwrap();
        assert!(matches!(
            downstream.next_subscription_event(&cx, &replacement).await.unwrap(),
            StdioSubscriptionEvent::Acknowledged(accepted) if accepted == filter
        ));
        assert_eq!(
            publisher
                .publish(ServerNotification::ToolsListChanged(None))
                .unwrap(),
            1
        );
        let StdioSubscriptionEvent::Notification(notification) = downstream
            .next_subscription_event(&cx, &replacement)
            .await
            .unwrap()
        else {
            panic!("the replacement listener must receive its own event");
        };
        assert_ne!(
            notification.encode().unwrap().params.unwrap()["_meta"][FINAL_SUBSCRIPTION_ID_META_KEY],
            2,
            "a replacement listener must not inherit the retired request ID",
        );
        assert_eq!(effects.calls.load(Ordering::Acquire), 2);
        downstream.close(&cx).await.unwrap();
        gateway.stop(&cx).await;
        running.stop(&cx).await;
    });
}

#[test]
fn native_websocket_proxy_duplicate_listener_does_not_replace_the_active_owner() {
    run(|cx| async move {
        let effects = Arc::new(Effects::default());
        let server = upstream(&effects, ProtocolPolicy::ModernOnly);
        let publisher = server.subscription_publisher();
        let running = Running::start(&cx, server).await;
        let proxy = connect(&cx, running.address, 42).await;
        let catalog = proxy.catalog_typed_with_cx(&cx).await.unwrap();
        let gateway = Server::new("websocket-listener-owner-gateway", "1")
            .protocol_policy(ProtocolPolicy::ModernOnly)
            .unwrap()
            .as_proxy_typed("ws", proxy, catalog)
            .unwrap()
            .build();
        let gateway = Running::start(&cx, gateway).await;
        let mut first = client(&cx, gateway.address, ProtocolPolicy::ModernOnly).await;
        let mut second = client(&cx, gateway.address, ProtocolPolicy::ModernOnly).await;
        let filter = SubscriptionFilter {
            tools_list_changed: Some(true),
            ..Default::default()
        };
        let first_owner = McpRequestCancellation::new();
        first
            .open_subscriptions_listener(&cx, filter.clone())
            .await
            .unwrap();
        assert!(matches!(
            first.next_subscription_event(&cx, &first_owner).await.unwrap(),
            StdioSubscriptionEvent::Acknowledged(accepted) if accepted == filter
        ));

        let second_owner = McpRequestCancellation::new();
        second
            .open_subscriptions_listener(&cx, filter)
            .await
            .unwrap();
        let refused = second
            .next_subscription_event(&cx, &second_owner)
            .await
            .unwrap_err();
        assert_eq!(refused.code, McpErrorCode::InvalidRequest);
        assert_eq!(
            publisher
                .publish(ServerNotification::ToolsListChanged(None))
                .unwrap(),
            1
        );
        let StdioSubscriptionEvent::Notification(notification) = first
            .next_subscription_event(&cx, &first_owner)
            .await
            .unwrap()
        else {
            panic!("a rejected owner must not cancel or consume the first listener");
        };
        assert_eq!(
            notification.encode().unwrap().method,
            "notifications/tools/list_changed"
        );
        let result = second
            .call_tool(
                &cx,
                "ws/echo",
                json!({"value": "refused listener still has a usable client"}),
            )
            .await
            .unwrap();
        let result: Value = serde_json::from_str(&result.encode().unwrap()).unwrap();
        assert_eq!(
            result["content"][0]["text"],
            "refused listener still has a usable client"
        );
        assert_eq!(effects.calls.load(Ordering::Acquire), 1);
        first.close(&cx).await.unwrap();
        second.close(&cx).await.unwrap();
        gateway.stop(&cx).await;
        running.stop(&cx).await;
    });
}

#[test]
fn native_websocket_proxy_listener_idle_timeout_preserves_ordinary_requests() {
    run(|cx| async move {
        let effects = Arc::new(Effects::default());
        let server = upstream(&effects, ProtocolPolicy::ModernOnly);
        let publisher = server.subscription_publisher();
        let running = Running::start(&cx, server).await;
        let transport =
            AsyncWsClientTransport::connect(&cx, &format!("ws://{}/mcp", running.address))
                .await
                .unwrap();
        let upstream = ClientBuilder::new()
            .protocol_plan(ClientProtocolPlan::websocket(ProtocolPolicy::ModernOnly))
            .subscription_timeout_policy(
                SubscriptionTimeoutPolicy::new(Duration::from_secs(1), Duration::from_secs(5))
                    .unwrap(),
            )
            .connect_websocket_with_cx(&cx, transport)
            .await
            .unwrap();
        let proxy = ProxyClient::from_websocket(upstream, 43).unwrap();
        let catalog = proxy.catalog_typed_with_cx(&cx).await.unwrap();
        let gateway = Server::new("websocket-listener-timeout-gateway", "1")
            .protocol_policy(ProtocolPolicy::ModernOnly)
            .unwrap()
            .as_proxy_typed("ws", proxy, catalog)
            .unwrap()
            .build();
        let gateway = Running::start(&cx, gateway).await;
        let mut downstream = client(&cx, gateway.address, ProtocolPolicy::ModernOnly).await;
        let cancellation = McpRequestCancellation::new();
        downstream
            .open_subscriptions_listener(
                &cx,
                SubscriptionFilter {
                    tools_list_changed: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            downstream
                .next_subscription_event(&cx, &cancellation)
                .await
                .unwrap(),
            StdioSubscriptionEvent::Acknowledged(_)
        ));
        // When the upstream subscription's 1s idle timeout fires, the gateway
        // terminates the downstream subscription lease cleanly (without
        // exposing internal upstream timeout details or tripping downstream
        // cancellation).
        let terminated = downstream
            .next_subscription_event(&cx, &cancellation)
            .await
            .unwrap_err();
        assert_eq!(terminated.code, McpErrorCode::RequestCancelled);
        assert!(!cancellation.is_cancel_requested());

        // The receive-turn limit must never drop the selected timeout's
        // cancellation write. Both the downstream and upstream connection
        // remain usable after the retired listener reports its outcome.
        let result = downstream
            .call_tool(&cx, "ws/echo", json!({"value": "after idle timeout"}))
            .await
            .unwrap();
        let result: Value = serde_json::from_str(&result.encode().unwrap()).unwrap();
        assert_eq!(result["content"][0]["text"], "after idle timeout");
        assert_eq!(effects.calls.load(Ordering::Acquire), 1);
        assert_eq!(
            publisher
                .publish(ServerNotification::ToolsListChanged(None))
                .unwrap(),
            0,
            "the upstream subscription must release its route after timeout",
        );
        downstream.close(&cx).await.unwrap();
        gateway.stop(&cx).await;
        running.stop(&cx).await;
    });
}

#[test]
fn native_websocket_proxy_discovers_and_forwards_core_results_losslessly() {
    run(|cx| async move {
        let effects = Arc::new(Effects::default());
        let running = Running::start(&cx, upstream(&effects, ProtocolPolicy::ModernOnly)).await;
        let proxy = connect(&cx, running.address, 17).await;
        let catalog = proxy.catalog_typed_with_cx(&cx).await.unwrap();
        assert_eq!(catalog.final_tools().unwrap().len(), 1);
        assert_eq!(catalog.final_resources().unwrap().len(), 1);
        assert_eq!(catalog.final_resource_templates().unwrap().len(), 1);
        assert_eq!(catalog.final_prompts().unwrap().len(), 1);
        let gateway = Server::new("websocket-gateway", "1")
            .protocol_policy(ProtocolPolicy::ModernOnly)
            .unwrap()
            .as_proxy_typed("ws", proxy, catalog)
            .unwrap()
            .build();

        let listed = complete(
            dispatch(&gateway, &cx, 1, "tools/list", json!({})).await,
            "tools/list",
        );
        assert_eq!(listed["tools"][0]["name"], "ws/echo");
        let resources = complete(
            dispatch(&gateway, &cx, 2, "resources/list", json!({})).await,
            "resources/list",
        );
        assert_eq!(resources["resources"][0]["uri"], RESOURCE);
        let templates = complete(
            dispatch(&gateway, &cx, 3, "resources/templates/list", json!({})).await,
            "resources/templates/list",
        );
        assert_eq!(templates["resourceTemplates"][0]["uriTemplate"], TEMPLATE);
        let prompts = complete(
            dispatch(&gateway, &cx, 4, "prompts/list", json!({})).await,
            "prompts/list",
        );
        assert_eq!(prompts["prompts"][0]["name"], "ws/welcome");

        for (id, is_error) in [(5, false), (6, true)] {
            let result = complete(
                dispatch(&gateway, &cx, id, "tools/call", json!({
                    "name": "ws/echo", "arguments": {"value": "native: 世界 + %2F", "toolError": is_error},
                })).await,
                "tools/call",
            );
            assert_eq!(result["content"][0]["text"], "native: 世界 + %2F");
            assert_eq!(result["structuredContent"]["echo"], "native: 世界 + %2F");
            if is_error {
                assert_eq!(result["isError"], true);
            } else {
                assert!(result.get("isError").is_none());
            }
            assert_opaque(&result, "tools/call");
        }
        let read = complete(
            dispatch(&gateway, &cx, 7, "resources/read", json!({"uri": RESOURCE})).await,
            "resources/read",
        );
        assert_eq!(read["contents"][0]["uri"], RESOURCE);
        assert_eq!(read["contents"][0]["text"], "upstream note: 世界 + %2F");
        assert_opaque(&read, "resources/read");
        let prompt = complete(
            dispatch(
                &gateway,
                &cx,
                8,
                "prompts/get",
                json!({
                    "name": "ws/welcome", "arguments": {"name": "Composer"},
                }),
            )
            .await,
            "prompts/get",
        );
        assert_eq!(
            prompt["messages"][0]["content"]["text"],
            "Welcome, Composer"
        );
        assert_opaque(&prompt, "prompts/get");
        let completed = complete(
            dispatch(
                &gateway,
                &cx,
                9,
                "completion/complete",
                json!({
                    "ref": {"type": "ref/prompt", "name": "ws/welcome"},
                    "argument": {"name": "name", "value": "Com"},
                }),
            )
            .await,
            "completion/complete",
        );
        assert_eq!(completed["completion"]["values"], json!(["Com-complete"]));
        assert_eq!(completed["completion"]["total"].to_string(), EXACT_INTEGER);
        assert_opaque(&completed, "completion/complete");

        let before = effects.calls.load(Ordering::Acquire);
        let refused = dispatch(
            &gateway,
            &cx,
            10,
            "tools/call",
            json!({
                "name": "echo", "arguments": {"value": "must not reach upstream"},
            }),
        )
        .await;
        assert!(
            refused.error.is_some(),
            "unprefixed names are not a second route"
        );
        assert_eq!(effects.calls.load(Ordering::Acquire), before);
        assert_eq!(before, 2);
        assert_eq!(effects.reads.load(Ordering::Acquire), 1);
        assert_eq!(effects.prompts.load(Ordering::Acquire), 1);
        assert_eq!(effects.completions.load(Ordering::Acquire), 1);
        drop(gateway);
        running.stop(&cx).await;
    });
}

struct ProgressCapture {
    cancellation: Option<McpRequestCancellation>,
    observed: Mutex<Vec<(String, Option<String>, Option<String>)>>,
}

impl NotificationSender for ProgressCapture {
    fn send_progress(&self, _: f64, _: Option<f64>, _: Option<&str>) {
        panic!("the modern proxy must preserve exact JSON numbers");
    }

    fn send_progress_exact(
        &self,
        progress: serde_json::Number,
        total: Option<serde_json::Number>,
        message: Option<&str>,
    ) {
        self.observed.lock().unwrap().push((
            progress.to_string(),
            total.map(|number| number.to_string()),
            message.map(str::to_owned),
        ));
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        }
    }
}

#[derive(Default)]
struct LiveNotifications {
    progress: Mutex<Vec<(String, Option<String>)>>,
    logs: Mutex<Vec<(McpLogLevel, Value)>>,
    changed: Notify,
}

impl NotificationSender for LiveNotifications {
    fn send_progress(&self, _: f64, _: Option<f64>, _: Option<&str>) {
        panic!("live modern progress uses exact JSON numbers");
    }

    fn send_progress_exact(
        &self,
        progress: serde_json::Number,
        total: Option<serde_json::Number>,
        _: Option<&str>,
    ) {
        self.progress
            .lock()
            .unwrap()
            .push((progress.to_string(), total.map(|number| number.to_string())));
        self.changed.notify_waiters();
    }

    fn send_log(&self, level: McpLogLevel, _: Option<&str>, data: Value) {
        self.logs.lock().unwrap().push((level, data));
        self.changed.notify_waiters();
    }
}

#[test]
fn native_websocket_proxy_preserves_mrtr_state_inputs_and_exact_open_results() {
    run(|cx| async move {
        const UPSTREAM_STATE: &str = "opaque-upstream:+%2F:世界";
        let listener = WebSocketListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut peer_task = cx
            .spawn(move |peer_cx| async move {
                let mut peer = scripted_upstream(&peer_cx, &listener).await;
                let list = upstream_request(&mut peer, &peer_cx, "tools/list").await;
                peer.send(
                    &peer_cx,
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        list.id.unwrap(),
                        json!({
                            "resultType": "complete", "ttlMs": 0, "cacheScope": "public",
                            "tools": [{"name": "confirm", "inputSchema": {"type": "object"}}],
                        }),
                    )),
                )
                .await
                .unwrap();

                let challenge: Value = serde_json::from_str(
                    r#"{"resultType":"input_required","requestState":"opaque-upstream:+%2F:世界",
                    "inputRequests":{"roots":{"method":"roots/list"}},
                    "vendorExact":922337203685477580812345678901234567890,
                    "vendorDecimal":1.2300e+42,"_meta":{"com.example/challenge":"retained"}}"#,
                )
                .unwrap();
                // First exercise the raw typed adapter; then issue the same
                // kind of challenge through the gateway's MRTR ownership
                // boundary. These are independent initial tool invocations.
                for round in 0..2 {
                    let initial = upstream_request(&mut peer, &peer_cx, "tools/call").await;
                    let parameters = initial.params.as_ref().unwrap();
                    assert_eq!(parameters["name"], "confirm");
                    assert_eq!(parameters["arguments"], json!({"subject": "original"}));
                    if round == 1 {
                        assert_eq!(parameters["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["roots"], json!({}));
                    }
                    assert!(parameters.get("requestState").is_none());
                    assert!(parameters.get("inputResponses").is_none());
                    peer.send(
                        &peer_cx,
                        &JsonRpcMessage::Response(JsonRpcResponse::success(
                            initial.id.unwrap(),
                            challenge.clone(),
                        )),
                    )
                    .await
                    .unwrap();
                }

                // A forged downstream retry must never reach this socket.
                // The one resumed call carries the original upstream state,
                // not the gateway's separately scoped continuation handle.
                let resumed = upstream_request(&mut peer, &peer_cx, "tools/call").await;
                let parameters = resumed.params.as_ref().unwrap();
                assert_eq!(parameters["name"], "confirm");
                assert_eq!(parameters["arguments"], json!({"subject": "original"}));
                assert_eq!(parameters["requestState"], UPSTREAM_STATE);
                assert_eq!(parameters["inputResponses"], json!({
                    "roots": {"roots": [{"uri": "file:///workspace/example", "name": "fixture"}]},
                }));
                let result: Value = serde_json::from_str(
                    r#"{"resultType":"complete","content":[{"type":"text","text":"resumed"}],
                    "vendorExact":922337203685477580812345678901234567890,
                    "vendorDecimal":1.2300e+42,"_meta":{"com.example/resume":"retained"}}"#,
                )
                .unwrap();
                peer.send(
                    &peer_cx,
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        resumed.id.unwrap(),
                        result,
                    )),
                )
                .await
                .unwrap();
                assert!(
                    peer.recv(&peer_cx).await.is_err(),
                    "a consumed continuation cannot produce another upstream request",
                );
            })
            .unwrap();
        let proxy = connect(&cx, address, 18).await;
        let catalog = proxy.catalog_typed_with_cx(&cx).await.unwrap();
        let raw_context = McpContext::new(cx.clone(), 49)
            .with_client_capabilities(ClientCapabilityInfo::default().with_roots(false));
        let raw = proxy
            .call_tool_typed_async(&raw_context, "confirm", json!({"subject": "original"}))
            .await
            .unwrap();
        let raw: Value = serde_json::from_str(&raw.encode().unwrap()).unwrap();
        assert_eq!(raw["resultType"], "input_required");
        assert_eq!(raw["requestState"], UPSTREAM_STATE);
        assert_eq!(
            raw["inputRequests"],
            json!({"roots": {"method": "roots/list"}})
        );
        assert_eq!(raw["vendorExact"].to_string(), EXACT_INTEGER);
        assert_eq!(raw["vendorDecimal"].to_string(), EXACT_DECIMAL);
        assert_eq!(raw["_meta"]["com.example/challenge"], "retained");
        let gateway = Server::new("websocket-gateway", "1")
            .protocol_policy(ProtocolPolicy::ModernOnly)
            .unwrap()
            .as_proxy_typed("ws", proxy, catalog)
            .unwrap()
            .build();
        let connection = ModernConnection::new();
        let initial = dispatch_on_connection(
            &gateway,
            &connection,
            &cx,
            50,
            json!({"name": "ws/confirm", "arguments": {"subject": "original"}}),
        )
        .await;
        assert!(
            initial.error.is_none(),
            "MRTR challenge: {:?}",
            initial.error
        );
        let challenge = initial.result.unwrap();
        assert_eq!(challenge["resultType"], "input_required");
        assert_eq!(
            challenge["inputRequests"],
            json!({"roots": {"method": "roots/list"}})
        );
        // The router deliberately issues its own challenge and does not copy
        // handler result siblings across that authority boundary. Exact open
        // fields are proven above at the adapter and below on completion.
        let state = challenge["requestState"].as_str().unwrap().to_owned();
        assert_ne!(
            state, UPSTREAM_STATE,
            "the gateway owns its downstream handle"
        );

        let retry = json!({
            "name": "ws/confirm", "arguments": {"subject": "original"},
            "requestState": state,
            "inputResponses": {"roots": {"roots": [{"uri": "file:///workspace/example", "name": "fixture"}]}},
        });
        let mut forged = retry.clone();
        forged["requestState"] = json!(format!("{state}-forged"));
        let refused = dispatch_on_connection(&gateway, &connection, &cx, 51, forged).await;
        assert!(refused.error.is_some());
        let result = complete(
            dispatch_on_connection(&gateway, &connection, &cx, 52, retry.clone()).await,
            "resumed tools/call",
        );
        assert_eq!(result["content"][0]["text"], "resumed");
        assert_eq!(result["vendorExact"].to_string(), EXACT_INTEGER);
        assert_eq!(result["vendorDecimal"].to_string(), EXACT_DECIMAL);
        assert_eq!(result["_meta"]["com.example/resume"], "retained");
        let replayed = dispatch_on_connection(&gateway, &connection, &cx, 53, retry).await;
        assert!(
            replayed.error.is_some(),
            "consumed continuation cannot run a second time"
        );
        drop(connection);
        drop(gateway);
        peer_task.join(&cx).await.unwrap();
    });
}

#[test]
fn native_websocket_proxy_correlates_numeric_progress_aliases_exactly_once() {
    run(|cx| async move {
        let listener = WebSocketListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut peer_task = cx
            .spawn(move |peer_cx| async move {
                let mut peer = scripted_upstream(&peer_cx, &listener).await;
                let call = upstream_request(&mut peer, &peer_cx, "tools/call").await;
                assert_eq!(call.params.as_ref().unwrap()["_meta"]["progressToken"], 42);
                for parameters in [
                    json!({"progressToken": "42", "progress": 99, "message": "unrelated string token"}),
                    serde_json::from_str(r#"{"progressToken":4.2e1,"progress":1.2300e+42,"total":1.230000e+45,"message":"numeric alias"}"#).unwrap(),
                ] {
                    peer.send(
                        &peer_cx,
                        &JsonRpcMessage::Request(JsonRpcRequest::notification(
                            "notifications/progress",
                            Some(parameters),
                        )),
                    )
                    .await
                    .unwrap();
                }
                peer.send(
                    &peer_cx,
                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                        call.id.unwrap(),
                        json!({"resultType": "complete", "content": []}),
                    )),
                )
                .await
                .unwrap();
            })
            .unwrap();
        let proxy = connect(&cx, address, 19).await;
        let capture = Arc::new(ProgressCapture {
            cancellation: None,
            observed: Mutex::new(Vec::new()),
        });
        let context = McpContext::new(cx.clone(), 60)
            .with_progress_reporter(ProgressReporter::with_marker(json!(42), capture.clone()));
        proxy
            .call_tool_typed_async(&context, "confirm", json!({}))
            .await
            .unwrap();
        assert_eq!(
            *capture.observed.lock().unwrap(),
            vec![(
                EXACT_DECIMAL.to_owned(),
                Some("1.230000e+45".to_owned()),
                Some("numeric alias".to_owned())
            )],
            "numeric aliases correlate once; the same-spelled string token remains unrelated",
        );
        peer_task.join(&cx).await.unwrap();
        drop(context);
        drop(proxy);
    });
}

#[test]
fn native_websocket_proxy_streams_bursts_and_scopes_log_intent_to_each_request() {
    run(|cx| async move {
        const BURST: usize = 80;
        let capture = Arc::new(LiveNotifications::default());
        let peer_capture = Arc::clone(&capture);
        let listener = WebSocketListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut peer_task = cx
            .spawn(move |peer_cx| async move {
                let mut peer = scripted_upstream(&peer_cx, &listener).await;
                for round in 0..2 {
                    let call = upstream_request(&mut peer, &peer_cx, "tools/call").await;
                    let parameters = call.params.as_ref().unwrap();
                    let marker = format!("live-notifications-{round}");
                    assert_eq!(parameters["_meta"]["progressToken"], marker);
                    if round == 0 {
                        assert_eq!(parameters["_meta"][FINAL_LOG_LEVEL_META_KEY], "info");
                    } else {
                        assert!(parameters["_meta"].get(FINAL_LOG_LEVEL_META_KEY).is_none());
                    }
                    for sequence in 1..=BURST {
                        let mut data = json!({"round": round, "sequence": sequence});
                        data["exact"] = serde_json::from_str(EXACT_INTEGER).unwrap();
                        data["decimal"] = serde_json::from_str(EXACT_DECIMAL).unwrap();
                        for (method, parameters) in [
                            ("notifications/message", json!({
                                "level": "info", "logger": "upstream.audit", "data": data,
                            })),
                            ("notifications/progress", json!({
                                "progressToken": marker, "progress": sequence, "total": BURST,
                            })),
                        ] {
                            peer.send(
                                &peer_cx,
                                &JsonRpcMessage::Request(JsonRpcRequest::notification(method, Some(parameters))),
                            )
                            .await
                            .unwrap();
                        }
                    }
                    // Both callback streams must advance before the terminal
                    // reply. The burst exceeds the client's bounded retained
                    // notification queue, which live delivery must bypass.
                    asupersync::time::timeout(
                        peer_cx.now(),
                        BOUND,
                        peer_capture.changed.wait_until(|| {
                            peer_capture.progress.lock().unwrap().len() == (round + 1) * BURST
                                && peer_capture.logs.lock().unwrap().len() == BURST
                        }),
                    )
                    .await
                    .expect("logs and progress reach their live request owners before completion");
                    peer.send(
                        &peer_cx,
                        &JsonRpcMessage::Response(JsonRpcResponse::success(
                            call.id.unwrap(),
                            json!({"resultType": "complete", "content": [{"type": "text", "text": format!("round-{round}")}]}),
                        )),
                    )
                    .await
                    .unwrap();
                }
            })
            .unwrap();
        let proxy = connect(&cx, address, 20).await;
        for round in 0..2 {
            let mut context = McpContext::new(cx.clone(), 61 + u64::try_from(round).unwrap())
                .with_log_sender(capture.clone())
                .with_progress_reporter(ProgressReporter::with_marker(
                    json!(format!("live-notifications-{round}")),
                    capture.clone(),
                ));
            if round == 0 {
                context = context.with_min_log_level(Some(McpLogLevel::Info));
            }
            let result = proxy
                .call_tool_typed_async(&context, "confirm", json!({"round": round}))
                .await
                .unwrap();
            let result: Value = serde_json::from_str(&result.encode().unwrap()).unwrap();
            assert_eq!(result["content"][0]["text"], format!("round-{round}"));
            assert_eq!(capture.progress.lock().unwrap().len(), (round + 1) * BURST);
            assert_eq!(capture.logs.lock().unwrap().len(), BURST);
        }
        for (index, (progress, total)) in capture.progress.lock().unwrap().iter().enumerate() {
            assert_eq!(progress, &(index % BURST + 1).to_string());
            assert_eq!(total.as_deref(), Some("80"));
        }
        for (index, (level, data)) in capture.logs.lock().unwrap().iter().enumerate() {
            assert_eq!(*level, McpLogLevel::Info);
            assert_eq!(data["round"], 0, "the second request had no logging intent");
            assert_eq!(data["sequence"], index + 1);
            assert_eq!(data["exact"].to_string(), EXACT_INTEGER);
            assert_eq!(data["decimal"].to_string(), EXACT_DECIMAL);
        }
        peer_task.join(&cx).await.unwrap();
        drop(proxy);
    });
}

#[test]
fn native_websocket_proxy_progress_cancellation_leaves_sibling_and_connection_usable() {
    run(|cx| async move {
        let effects = Arc::new(Effects::default());
        let running = Running::start(&cx, upstream(&effects, ProtocolPolicy::ModernOnly)).await;
        let proxy = connect(&cx, running.address, 21).await;
        let sibling = connect(&cx, running.address, 22).await;
        let cancellation = McpRequestCancellation::new();
        let reporter = Arc::new(ProgressCapture {
            cancellation: Some(cancellation.clone()),
            observed: Mutex::new(Vec::new()),
        });
        let context = McpContext::new(cx.clone(), 70)
            .with_request_cancellation(cancellation)
            .with_progress_reporter(ProgressReporter::with_marker(
                json!("downstream-progress"),
                reporter.clone(),
            ));
        let error = proxy
            .call_tool_typed_async(&context, "echo", json!({"hold": true}))
            .await
            .unwrap_err();
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert_eq!(
            *reporter.observed.lock().unwrap(),
            vec![(
                EXACT_INTEGER.to_owned(),
                None,
                Some("upstream is waiting".to_owned()),
            )]
        );
        assert!(
            !cx.is_cancel_requested(),
            "downstream request cancellation is not connection authority"
        );
        asupersync::time::timeout(
            cx.now(),
            BOUND,
            effects
                .changed
                .wait_until(|| effects.held_dropped.load(Ordering::Acquire) == 1),
        )
        .await
        .expect("upstream observes cancellation and releases its handler");

        for (id, route) in [(71, &sibling), (72, &proxy)] {
            let result = route
                .call_tool_typed_async(
                    &McpContext::new(cx.clone(), id),
                    "echo",
                    json!({"value": "still live"}),
                )
                .await
                .unwrap();
            let result: Value = serde_json::from_str(&result.encode().unwrap()).unwrap();
            assert_eq!(result["content"][0]["text"], "still live");
        }
        assert_eq!(effects.calls.load(Ordering::Acquire), 3);
        drop(context);
        drop(proxy);
        drop(sibling);
        running.stop(&cx).await;
    });
}

#[test]
fn native_websocket_proxy_operation_deadline_cleans_up_before_connection_reuse() {
    run(|cx| async move {
        let effects = Arc::new(Effects::default());
        let running = Running::start(&cx, upstream(&effects, ProtocolPolicy::ModernOnly)).await;
        let proxy = connect(&cx, running.address, 23).await;
        let context = McpContext::new(cx.clone(), 73)
            .with_operation_deadline(Some(cx.now().saturating_add_nanos(1_000_000_000)));
        let error = proxy
            .call_tool_typed_async(&context, "echo", json!({"hold": true}))
            .await
            .unwrap_err();
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert_eq!(effects.calls.load(Ordering::Acquire), 1);
        assert!(!context.request_cancellation().is_cancel_requested());
        assert!(!cx.is_cancel_requested());
        asupersync::time::timeout(
            cx.now(),
            BOUND,
            effects
                .changed
                .wait_until(|| effects.held_dropped.load(Ordering::Acquire) == 1),
        )
        .await
        .expect("request-local deadline reaches the upstream cancellation lifecycle");
        let result = proxy
            .call_tool_typed_async(
                &McpContext::new(cx.clone(), 74),
                "echo",
                json!({"value": "after deadline"}),
            )
            .await
            .unwrap();
        let result: Value = serde_json::from_str(&result.encode().unwrap()).unwrap();
        assert_eq!(result["content"][0]["text"], "after deadline");
        assert_eq!(effects.calls.load(Ordering::Acquire), 2);
        drop(context);
        drop(proxy);
        running.stop(&cx).await;
    });
}

#[test]
fn native_websocket_proxy_cancels_queued_request_without_sending_or_interrupting_owner() {
    run(|cx| async move {
        let effects = Arc::new(Effects::default());
        let running = Running::start(&cx, upstream(&effects, ProtocolPolicy::ModernOnly)).await;
        let proxy = connect(&cx, running.address, 24).await;
        let owner_cancellation = McpRequestCancellation::new();
        let owner_token = owner_cancellation.clone();
        let owner_proxy = proxy.clone();
        let mut owner_task = cx
            .spawn(move |owner_cx| async move {
                let context = McpContext::new(owner_cx, 75).with_request_cancellation(owner_token);
                owner_proxy
                    .call_tool_typed_async(&context, "echo", json!({"hold": true}))
                    .await
            })
            .unwrap();
        asupersync::time::timeout(
            cx.now(),
            BOUND,
            effects
                .changed
                .wait_until(|| effects.calls.load(Ordering::Acquire) == 1),
        )
        .await
        .expect("the first request owns the upstream receive driver");

        let queued_cancellation = McpRequestCancellation::new();
        let queued_context =
            McpContext::new(cx.clone(), 76).with_request_cancellation(queued_cancellation.clone());
        let mut queued = Box::pin(proxy.call_tool_typed_async(
            &queued_context,
            "echo",
            json!({"value": "must not be sent"}),
        ));
        std::future::poll_fn(|task| {
            assert!(queued.as_mut().poll(task).is_pending());
            Poll::Ready(())
        })
        .await;
        queued_cancellation.cancel();
        assert_eq!(
            queued.await.unwrap_err().code,
            McpErrorCode::RequestCancelled
        );
        assert_eq!(effects.calls.load(Ordering::Acquire), 1);
        assert_eq!(effects.held_dropped.load(Ordering::Acquire), 0);
        assert!(!owner_cancellation.is_cancel_requested());
        assert!(!cx.is_cancel_requested());

        owner_cancellation.cancel();
        assert_eq!(
            owner_task.join(&cx).await.unwrap().unwrap_err().code,
            McpErrorCode::RequestCancelled,
        );
        asupersync::time::timeout(
            cx.now(),
            BOUND,
            effects
                .changed
                .wait_until(|| effects.held_dropped.load(Ordering::Acquire) == 1),
        )
        .await
        .expect("cancelling the owner releases its upstream handler");
        let result = proxy
            .call_tool_typed_async(
                &McpContext::new(cx.clone(), 77),
                "echo",
                json!({"value": "after queued cancellation"}),
            )
            .await
            .unwrap();
        let result: Value = serde_json::from_str(&result.encode().unwrap()).unwrap();
        assert_eq!(result["content"][0]["text"], "after queued cancellation");
        assert_eq!(effects.calls.load(Ordering::Acquire), 2);
        drop(queued_context);
        drop(proxy);
        running.stop(&cx).await;
    });
}

#[test]
fn native_websocket_proxy_rejects_malformed_catalog_without_answering_upstream() {
    run(|cx| async move {
        let effects = Arc::new(Effects::default());
        let healthy = Running::start(&cx, upstream(&effects, ProtocolPolicy::ModernOnly)).await;
        let sibling = connect(&cx, healthy.address, 31).await;
        let listener = WebSocketListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut peer_task = cx.spawn(move |peer_cx| async move {
            let upgrade = listener.accept(&peer_cx).await.unwrap();
            assert_eq!(upgrade.path(), "/mcp");
            let mut peer = upgrade.into_admission().unwrap().complete(&peer_cx).await.unwrap();
            let JsonRpcMessage::Request(discovery) = peer.recv(&peer_cx).await.unwrap() else {
                panic!("upstream first receives modern discovery");
            };
            assert_eq!(discovery.method, "server/discover");
            peer.send(&peer_cx, &JsonRpcMessage::Response(JsonRpcResponse::success(
                discovery.id.unwrap(), json!({
                    "resultType": "complete", "supportedVersions": [FINAL_PROTOCOL_VERSION],
                    "capabilities": {"tools": {}}, "ttlMs": 0, "cacheScope": "public",
                }),
            ))).await.unwrap();
            let JsonRpcMessage::Request(list) = peer.recv(&peer_cx).await.unwrap() else {
                panic!("discovery is followed by tools/list");
            };
            assert_eq!(list.method, "tools/list");
            peer.send(&peer_cx, &JsonRpcMessage::Response(JsonRpcResponse::success(
                list.id.unwrap(), json!({
                    "resultType": "complete", "ttlMs": 0, "cacheScope": "public",
                    "tools": [
                        {"name": "valid-prefix", "inputSchema": {"type": "object"}},
                        {"name": "invalid-sibling", "inputSchema": "not a schema object"},
                    ],
                }),
            ))).await.unwrap();
            // Client-ingress result failure cannot become a server-ingress
            // JSON-RPC error written back to this peer. Dropping the failed
            // route closes its owned socket without partial catalog traffic.
            assert!(peer.recv(&peer_cx).await.is_err(), "malformed upstream result must not provoke a response or another catalog request");
        }).unwrap();
        let invalid = connect(&cx, address, 32).await;
        assert!(
            invalid.catalog_typed_with_cx(&cx).await.is_err(),
            "one bad tool rejects the whole upstream catalog"
        );
        drop(invalid);
        peer_task.join(&cx).await.unwrap();
        let result = sibling
            .call_tool_typed_async(
                &McpContext::new(cx.clone(), 80),
                "echo",
                json!({"value": "healthy sibling"}),
            )
            .await
            .unwrap();
        let result: Value = serde_json::from_str(&result.encode().unwrap()).unwrap();
        assert_eq!(result["content"][0]["text"], "healthy sibling");
        assert_eq!(effects.calls.load(Ordering::Acquire), 1);
        drop(sibling);
        healthy.stop(&cx).await;
    });
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn native_websocket_proxy_refuses_legacy_client_before_catalog_or_tool_effects() {
    run(|cx| async move {
        let effects = Arc::new(Effects::default());
        let running = Running::start(&cx, upstream(&effects, ProtocolPolicy::LegacyOnly)).await;
        let legacy = client(&cx, running.address, ProtocolPolicy::LegacyOnly).await;
        assert!(ProxyClient::from_websocket(legacy, 41).is_err());
        assert_eq!(effects.calls.load(Ordering::Acquire), 0);
        assert_eq!(effects.reads.load(Ordering::Acquire), 0);
        assert_eq!(effects.prompts.load(Ordering::Acquire), 0);
        assert_eq!(effects.completions.load(Ordering::Acquire), 0);
        running.stop(&cx).await;
    });
}
