use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::test_utils::run_test;
use fastmcp_protocol::{
    ClientCapabilities, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse,
    MCP_APPS_HOST_VIEW_PROTOCOL_VERSION, McpAppsBridgeDirection, McpAppsBridgeError,
    McpAppsBridgeImplementation, McpAppsBridgeLifecycle,
    McpAppsControlDisposition, McpAppsJsonRpcRequestId, McpAppsPinnedHostCapabilities,
    McpAppsPinnedHostContext, RequestId, SamplingCapability,
};
use fastmcp_transport::websocket::AsyncWsServerTransport;
use serde_json::{Value, json};

use super::super::{
    McpAppsCatalogBinding, McpAppsInMemoryWireViewTransport, McpAppsWireBridgeTransport,
    McpAppsWireHost,
    McpAppsWireHostConfiguration, McpAppsWireHostEffects, McpAppsWireHostPolicy,
    mcp_apps_in_memory_wire_pair,
};
use super::{Cx, McpAppsHostError, McpAppsRoutedMethod, McpRequestCancellation, WebSocketClient};
use crate::{
    AsyncWsClientTransport, ClientBuilder, ClientProtocolPlan, McpAppsClientSettings,
    ProtocolPolicy, RequestTimeoutPolicy,
};

type Peer = AsyncWsServerTransport<VirtualTcpStream>;

struct Options {
    client_apps: bool,
    server_apps: bool,
    tasks: bool,
    sampling: bool,
    timeout: RequestTimeoutPolicy,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            client_apps: true,
            server_apps: true,
            tasks: false,
            sampling: true,
            timeout: RequestTimeoutPolicy::default(),
        }
    }
}

fn streams() -> (VirtualTcpStream, VirtualTcpStream) {
    VirtualTcpStream::pair(
        "127.0.0.1:45161".parse().unwrap(),
        "127.0.0.1:45162".parse().unwrap(),
    )
}

async fn respond(peer: &mut Peer, cx: &Cx, id: i64, result: Value) {
    peer.send(
        cx,
        &JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), result)),
    )
    .await
    .unwrap();
}

async fn next_request(peer: &mut Peer, cx: &Cx) -> JsonRpcRequest {
    let JsonRpcMessage::Request(request) = peer.recv(cx).await.unwrap() else {
        panic!("expected a client request or cancellation notification");
    };
    request
}

async fn connect<IO>(
    cx: &Cx,
    stream: IO,
    peer: &mut Peer,
    options: Options,
) -> WebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut discovery = json!({
        "resultType": "complete",
        "supportedVersions": ["2026-07-28"],
        "capabilities": {"tools": {}, "resources": {}, "prompts": {}, "extensions": {}},
        "ttlMs": 0, "cacheScope": "private",
        "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "apps-ws-peer", "version": "1"}}
    });
    if options.server_apps {
        discovery["capabilities"]["extensions"]["io.modelcontextprotocol/ui"] = json!({});
    }
    if options.tasks {
        discovery["capabilities"]["extensions"]["io.modelcontextprotocol/tasks"] = json!({});
    }
    respond(peer, cx, 1, discovery).await;
    let mut builder = ClientBuilder::new()
        .protocol_plan(ClientProtocolPlan::websocket(ProtocolPolicy::ModernOnly))
        .capabilities(ClientCapabilities {
            sampling: options.sampling.then(SamplingCapability::default),
            ..ClientCapabilities::default()
        })
        .request_timeout_policy(options.timeout);
    if options.client_apps {
        builder = builder.mcp_apps(
            McpAppsClientSettings::new(vec![fastmcp_protocol::MCP_APPS_HTML_MIME_TYPE.into()])
                .unwrap(),
        );
    }
    let client = builder
        .connect_websocket_with_cx(cx, AsyncWsClientTransport::from_upgraded(stream))
        .await
        .unwrap();
    let discovery = next_request(peer, cx).await;
    assert_eq!(discovery.method, "server/discover");
    assert_eq!(discovery.id, Some(RequestId::Number(1)));
    client
}

fn configuration() -> McpAppsWireHostConfiguration {
    McpAppsWireHostConfiguration {
        host_info: McpAppsBridgeImplementation {
            name: "apps-host".to_owned(),
            version: "1".to_owned(),
        },
        host_capabilities: McpAppsPinnedHostCapabilities {
            server_tools: Some(Default::default()),
            server_resources: Some(Default::default()),
            ..McpAppsPinnedHostCapabilities::default()
        },
        host_context: McpAppsPinnedHostContext::default(),
    }
}

async fn activate<T: McpAppsWireBridgeTransport, P: McpAppsWireHostPolicy>(
    host: &mut McpAppsWireHost<T, P>,
    view: &mut McpAppsInMemoryWireViewTransport,
    cx: &Cx,
) {
    enqueue(
        view,
        cx,
        "initialize",
        "ui/initialize",
        json!({
            "appInfo": {"name": "view", "version": "1"},
            "appCapabilities": {},
            "protocolVersion": MCP_APPS_HOST_VIEW_PROTOCOL_VERSION
        }),
    )
    .await;
    host.process_next(cx).await.unwrap();
    assert!(view_response(view, cx).await.get("result").is_some());
    view.send_to_host(
        cx,
        json!({"jsonrpc": "2.0", "method": "ui/notifications/initialized"}).to_string(),
    )
    .await
    .unwrap();
    host.process_next(cx).await.unwrap();
    assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
}

async fn enqueue(
    view: &mut McpAppsInMemoryWireViewTransport,
    cx: &Cx,
    id: &str,
    method: &str,
    params: Value,
) {
    view.send_to_host(
        cx,
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string(),
    )
    .await
    .unwrap();
}

async fn cancel_view(view: &mut McpAppsInMemoryWireViewTransport, cx: &Cx, id: &str) {
    view.send_to_host(
        cx,
        json!({
            "jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": id}
        })
        .to_string(),
    )
    .await
    .unwrap();
}

async fn view_response(view: &mut McpAppsInMemoryWireViewTransport, cx: &Cx) -> Value {
    serde_json::from_str(&view.receive_from_host(cx).await.unwrap()).unwrap()
}

async fn request<T: McpAppsWireBridgeTransport, P: McpAppsWireHostPolicy>(
    host: &mut McpAppsWireHost<T, P>,
    view: &mut McpAppsInMemoryWireViewTransport,
    cx: &Cx,
    id: &str,
    method: &str,
    params: Value,
) -> Value {
    enqueue(view, cx, id, method, params).await;
    host.process_next(cx).await.unwrap();
    let response = view_response(view, cx).await;
    assert_eq!(response["id"], id);
    response
}

async fn request_while_pending<F>(
    drive: &mut Pin<Box<F>>,
    peer: &mut Peer,
    cx: &Cx,
) -> JsonRpcRequest
where
    F: Future<Output = Result<(), McpAppsHostError>>,
{
    let mut receive = Box::pin(peer.recv(cx));
    poll_fn(|task| {
        assert!(drive.as_mut().poll(task).is_pending());
        match receive.as_mut().poll(task) {
            Poll::Ready(Ok(JsonRpcMessage::Request(request))) => Poll::Ready(request),
            Poll::Ready(other) => panic!("expected an in-flight client request: {other:?}"),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

fn complete(text: &str) -> Value {
    json!({"resultType": "complete", "content": [{"type": "text", "text": text}]})
}

fn callable_tools(names: &[&str]) -> Value {
    json!({"resultType": "complete", "tools": names.iter().map(|name| json!({
        "name": name, "inputSchema": {"type": "object"}
    })).collect::<Vec<_>>(), "ttlMs": 0, "cacheScope": "private"})
}

fn input_required(state: &str) -> Value {
    json!({
        "resultType": "input_required", "requestState": state,
        "inputRequests": {"sample": {"method": "sampling/createMessage", "params": {
            "messages": [{"role": "user", "content": {"type": "text", "text": "Review this View"}}],
            "maxTokens": 32
        }}}
    })
}

fn input_response() -> Value {
    json!({"sample": {
        "role": "assistant", "model": "host-approved",
        "content": {"type": "text", "text": "approved answer"}, "stopReason": "endTurn"
    }})
}

struct InputEffects {
    responses: Value,
    calls: Arc<Mutex<Vec<Value>>>,
}

impl InputEffects {
    fn new() -> Self {
        Self {
            responses: input_response(),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[allow(clippy::unused_async_trait_impl, reason = "public async consent callback")]
impl McpAppsWireHostEffects for InputEffects {
    async fn resolve_server_input(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: McpAppsRoutedMethod,
        params: &Value,
        required: &fastmcp_protocol::InputRequiredResult,
    ) -> Result<fastmcp_protocol::FinalInputResponses, McpAppsHostError> {
        super::super::wire_policy_checkpoint(cx, cancellation)?;
        assert_eq!(method, McpAppsRoutedMethod::ToolsCall);
        self.calls.lock().unwrap().push(json!({"params": params, "state": required.request_state()}));
        Ok(serde_json::from_value(self.responses.clone()).unwrap())
    }
}

#[test]
fn public_websocket_apps_forwards_reused_methods_with_fresh_core_ids() {
    run_test(|| async {
        let cx = Cx::current().unwrap();
        let (stream, server) = streams();
        let mut peer = Peer::from_upgraded(server);
        let mut client = connect(&cx, stream, &mut peer, Options::default()).await;
        assert!(client.mcp_apps_active());
        let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
        let mut host = client.mcp_apps_wire_host(transport, configuration()).unwrap();
        host.bind_server_catalogs(
            McpAppsCatalogBinding {
                view_id: "view".into(), resource_uri: "ui://view".into(),
                origin: "https://view.example".into(), principal_id: "owner".into(),
                server_id: "peer".into(), revision: "one".into(),
            },
            true,
        ).unwrap();
        activate(&mut host, &mut view, &cx).await;
        for (index, (method, params, payload)) in [
            ("tools/call", json!({"name": "ordinary"}), json!({"content": [{"type": "text", "text": "ordinary"}]})),
            ("resources/read", json!({"uri": "test://entry"}), json!({
                "contents": [{"uri": "test://entry", "text": "resource"}],
                "ttlMs": 0, "cacheScope": "private"
            })),
            ("resources/list", json!({}), json!({"resources": [], "ttlMs": 0, "cacheScope": "private"})),
            ("resources/templates/list", json!({}), json!({"resourceTemplates": [], "ttlMs": 0, "cacheScope": "private"})),
            ("prompts/list", json!({}), json!({"prompts": [], "ttlMs": 0, "cacheScope": "private"})),
        ].into_iter().enumerate() {
            let id = i64::try_from(index).unwrap() + 3;
            if method == "tools/call" {
                respond(&mut peer, &cx, 2, callable_tools(&["ordinary"])).await;
            }
            let mut result = payload.clone();
            result["resultType"] = json!("complete");
            respond(&mut peer, &cx, id, result).await;
            let response = request(&mut host, &mut view, &cx, "same-view-id", method, params.clone()).await;
            if method == "resources/read" {
                assert_eq!(response["result"]["contents"], payload["contents"]);
                assert!(response["result"].get("resultType").is_none());
            } else {
                assert_eq!(response["result"], payload);
            }
            if method == "tools/call" {
                let catalog = next_request(&mut peer, &cx).await;
                assert_eq!(catalog.id, Some(RequestId::Number(2)));
                assert_eq!(catalog.method, "tools/list");
            }
            let forwarded = next_request(&mut peer, &cx).await;
            assert_eq!(forwarded.id, Some(RequestId::Number(id)));
            assert_eq!(forwarded.method, method);
            let forwarded = forwarded.params.unwrap();
            assert_eq!(forwarded["_meta"]["io.modelcontextprotocol/protocolVersion"], "2026-07-28");
            assert!(!forwarded.to_string().contains("same-view-id"));
            for (key, value) in params.as_object().unwrap() {
                assert_eq!(&forwarded[key], value);
            }
        }
        drop(host);
        client.close(&cx).await.unwrap();
        assert!(peer.recv(&cx).await.is_err(), "no Apps frame or extra core RPC");
    });
}

#[test]
fn public_websocket_apps_tool_visibility_rechecks_before_every_call() {
    run_test(|| async {
        let cx = Cx::current().unwrap();
        let (stream, server) = streams();
        let mut peer = Peer::from_upgraded(server);
        let mut client = connect(&cx, stream, &mut peer, Options::default()).await;
        let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
        let mut host = client
            .mcp_apps_wire_host(transport, configuration())
            .unwrap();
        activate(&mut host, &mut view, &cx).await;
        let mut page = callable_tools(&["selected"]);
        page["ttlMs"] = json!(60_000);
        page["tools"][0]["_meta"] = json!({"ui": {"visibility": ["app"]}});
        respond(&mut peer, &cx, 2, page.clone()).await;
        respond(&mut peer, &cx, 3, complete("visible")).await;
        assert_eq!(
            request(
                &mut host,
                &mut view,
                &cx,
                "same-view",
                "tools/call",
                json!({"name":"selected"})
            )
            .await["result"]["content"][0]["text"],
            "visible"
        );
        let catalog = next_request(&mut peer, &cx).await;
        assert_eq!(catalog.method, "tools/list");
        assert_eq!(catalog.id, Some(RequestId::Number(2)));
        let invoked = next_request(&mut peer, &cx).await;
        assert_eq!(invoked.method, "tools/call");
        assert_eq!(invoked.id, Some(RequestId::Number(3)));

        page["tools"][0]["_meta"]["ui"]["visibility"] = json!(["model"]);
        respond(&mut peer, &cx, 4, page).await;
        let denied = request(
            &mut host,
            &mut view,
            &cx,
            "same-view",
            "tools/call",
            json!({"name":"selected"}),
        )
        .await;
        assert!(denied.get("error").is_some());
        assert!(denied.get("result").is_none());
        assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
        let fresh = next_request(&mut peer, &cx).await;
        assert_eq!(fresh.method, "tools/list");
        assert_eq!(fresh.id, Some(RequestId::Number(4)));
        drop(host);
        client.close(&cx).await.unwrap();
        assert!(
            peer.recv(&cx).await.is_err(),
            "revoked visibility sends no tools/call"
        );
    });
}

#[test]
fn public_websocket_apps_requires_live_bilateral_activation() {
    run_test(|| async {
        let cx = Cx::current().unwrap();
        for (client_apps, server_apps) in [(false, true), (true, false)] {
            let (stream, server) = streams();
            let mut peer = Peer::from_upgraded(server);
            let mut client = connect(&cx, stream, &mut peer, Options {
                client_apps, server_apps, ..Options::default()
            }).await;
            assert!(!client.mcp_apps_active());
            let (transport, _view) = mcp_apps_in_memory_wire_pair(1);
            assert!(matches!(
                client.mcp_apps_wire_host(transport, configuration()),
                Err(McpAppsHostError::NotNegotiated)
            ));
            client.close(&cx).await.unwrap();
            assert!(peer.recv(&cx).await.is_err(), "refusal must precede any RPC");
        }
        let (stream, server) = streams();
        let mut peer = Peer::from_upgraded(server);
        let mut client = connect(&cx, stream, &mut peer, Options::default()).await;
        client.close(&cx).await.unwrap();
        let (transport, _view) = mcp_apps_in_memory_wire_pair(1);
        assert!(!client.mcp_apps_active());
        assert!(matches!(
            client.mcp_apps_wire_host(transport, configuration()),
            Err(McpAppsHostError::NotNegotiated)
        ));
    });
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn public_websocket_apps_refuses_exact_legacy_before_view_dispatch() {
    run_test(|| async {
        let cx = Cx::current().unwrap();
        let (stream, server) = streams();
        let mut peer = Peer::from_upgraded(server);
        respond(&mut peer, &cx, 1, json!({
            "protocolVersion": "2024-11-05", "capabilities": {},
            "serverInfo": {"name": "legacy", "version": "1"}
        })).await;
        let mut client = ClientBuilder::new()
            .protocol_plan(ClientProtocolPlan::websocket(ProtocolPolicy::LegacyOnly))
            .connect_websocket_with_cx(&cx, AsyncWsClientTransport::from_upgraded(stream))
            .await.unwrap();
        assert_eq!(next_request(&mut peer, &cx).await.method, "initialize");
        assert_eq!(next_request(&mut peer, &cx).await.method, "notifications/initialized");
        let (transport, _view) = mcp_apps_in_memory_wire_pair(1);
        assert!(matches!(
            client.mcp_apps_wire_host(transport, configuration()),
            Err(McpAppsHostError::NotNegotiated)
        ));
        client.close(&cx).await.unwrap();
        assert!(peer.recv(&cx).await.is_err());
    });
}

#[test]
fn public_websocket_apps_mrtr_requires_this_views_capability_and_exact_input_round() {
    run_test(|| async {
        let cx = Cx::current().unwrap();
        for case in ["approved", "foreign-key", "missing-capability"] {
            let (stream, server) = streams();
            let mut peer = Peer::from_upgraded(server);
            let mut client = connect(&cx, stream, &mut peer, Options {
                sampling: case != "missing-capability", ..Options::default()
            }).await;
            let mut effects = InputEffects::new();
            if case == "foreign-key" {
                effects.responses = json!({"other-round": input_response()["sample"]});
            }
            let calls = Arc::clone(&effects.calls);
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let mut host = client.mcp_apps_wire_host(transport, configuration()).unwrap().with_effects(effects);
            activate(&mut host, &mut view, &cx).await;
            respond(&mut peer, &cx, 2, callable_tools(&["job"])).await;
            respond(&mut peer, &cx, 3, input_required("private-round")).await;
            if case == "approved" {
                respond(&mut peer, &cx, 4, complete("continued")).await;
            }
            let response = request(&mut host, &mut view, &cx, "view-round", "tools/call", json!({
                "name": "job", "arguments": {"value": 7}
            })).await;
            assert_eq!(response.get("result").is_some(), case == "approved");
            assert_eq!(calls.lock().unwrap().len(), usize::from(case != "missing-capability"));
            assert_eq!(next_request(&mut peer, &cx).await.method, "tools/list");
            let first = next_request(&mut peer, &cx).await;
            assert_eq!(first.id, Some(RequestId::Number(3)));
            if case == "approved" {
                let continued = next_request(&mut peer, &cx).await;
                assert_eq!(continued.id, Some(RequestId::Number(4)));
                assert_eq!(continued.method, "tools/call");
                let params = continued.params.unwrap();
                assert_eq!(params["requestState"], "private-round");
                assert_eq!(params["inputResponses"], input_response());
                assert_eq!(params["arguments"], json!({"value": 7}));
            }
            let healthy_id = if case == "approved" { 6 } else { 5 };
            respond(&mut peer, &cx, healthy_id - 1, callable_tools(&["healthy"])).await;
            respond(&mut peer, &cx, healthy_id, complete("healthy")).await;
            let healthy = request(&mut host, &mut view, &cx, "view-round", "tools/call", json!({"name": "healthy"})).await;
            assert_eq!(healthy["result"]["content"][0]["text"], "healthy");
            assert_eq!(next_request(&mut peer, &cx).await.method, "tools/list");
            let healthy = next_request(&mut peer, &cx).await;
            assert_eq!(healthy.id, Some(RequestId::Number(healthy_id)));
            let params = healthy.params.unwrap();
            assert!(params.get("requestState").is_none());
            assert!(params.get("inputResponses").is_none());
            drop(host);
            client.close(&cx).await.unwrap();
            assert!(peer.recv(&cx).await.is_err());
        }
    });
}

async fn cancellation_probe(abandon_drive: bool) {
    let cx = Cx::current().unwrap();
    let (stream, server) = streams();
    let mut peer = Peer::from_upgraded(server);
    let mut client = connect(&cx, stream, &mut peer, Options::default()).await;
    let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
    let mut host = client
        .mcp_apps_wire_host(transport, configuration())
        .unwrap()
        .with_effects(());
    activate(&mut host, &mut view, &cx).await;

    // An absent-ID control is inert and cannot manufacture upstream cleanup.
    view.send_to_host(
        &cx,
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}})
            .to_string(),
    )
    .await
    .unwrap();
    host.process_next(&cx).await.unwrap();
    {
        let mut receive = Box::pin(peer.recv(&cx));
        assert!(poll_fn(|task| Poll::Ready(receive.as_mut().poll(task))).await.is_pending());
    }

    enqueue(&mut view, &cx, "owned-view-id", "tools/call", json!({"name": "slow"})).await;
    let mut drive = Box::pin(host.process_next(&cx));
    let catalog = request_while_pending(&mut drive, &mut peer, &cx).await;
    assert_eq!(catalog.id, Some(RequestId::Number(2)));
    assert_eq!(catalog.method, "tools/list");
    respond(&mut peer, &cx, 2, callable_tools(&["slow"])).await;
    let original = request_while_pending(&mut drive, &mut peer, &cx).await;
    assert_eq!(original.id, Some(RequestId::Number(3)));
    assert_eq!(original.method, "tools/call");

    if abandon_drive {
        drop(drive);
        assert_eq!(
            host.admission.admit_control(
                McpAppsBridgeDirection::ViewToHost,
                McpAppsRoutedMethod::Cancelled,
                Some(&json!({"requestId": "owned-view-id"})),
            ).unwrap(),
            McpAppsControlDisposition::Bound(McpAppsJsonRpcRequestId::String("owned-view-id".into())),
            "dropping a drive alone must not release View correlation",
        );
        cancel_view(&mut view, &cx, "owned-view-id").await;
        host.process_next(&cx).await.unwrap();
    } else {
        // This carrier wake is the only incoming activity. The MCP peer stays
        // silent, so cleanup cannot depend on a response or a second RPC.
        cancel_view(&mut view, &cx, "owned-view-id").await;
        drive.await.unwrap();
    }

    assert_eq!(
        host.admission.admit_control(
            McpAppsBridgeDirection::ViewToHost,
            McpAppsRoutedMethod::Cancelled,
            Some(&json!({"requestId": "owned-view-id"})),
        ),
        Err(McpAppsBridgeError::UnknownCorrelation),
    );
    let control = next_request(&mut peer, &cx).await;
    assert_eq!(control.method, "notifications/cancelled");
    assert!(control.id.is_none());
    assert_eq!(control.params.unwrap()["requestId"], 3);

    // Retired core ID 3 is discarded even though the View reuses its own ID.
    respond(&mut peer, &cx, 3, complete("late cancelled result")).await;
    respond(&mut peer, &cx, 4, callable_tools(&["healthy"])).await;
    respond(&mut peer, &cx, 5, complete("healthy successor")).await;
    let healthy = request(
        &mut host, &mut view, &cx, "owned-view-id", "tools/call", json!({"name": "healthy"}),
    ).await;
    assert_eq!(healthy["result"]["content"][0]["text"], "healthy successor");
    assert_eq!(next_request(&mut peer, &cx).await.method, "tools/list");
    let successor = next_request(&mut peer, &cx).await;
    assert_eq!(successor.method, "tools/call");
    assert_eq!(successor.id, Some(RequestId::Number(5)));
    assert_eq!(successor.params.unwrap()["name"], "healthy");
    assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
    drop(host);
    assert!(client.retired_requests.is_empty());
    client.close(&cx).await.unwrap();
    assert!(peer.recv(&cx).await.is_err(), "exactly one cancellation and no replay");
}

#[test]
fn public_websocket_apps_view_cancel_retires_upstream_before_connection_reuse() {
    run_test(|| cancellation_probe(false));
}

#[test]
fn public_websocket_apps_dropped_drive_retains_view_id_and_resumes_native_cleanup() {
    run_test(|| cancellation_probe(true));
}

#[derive(Default)]
struct WriteGate {
    blocked: AtomicBool,
    remaining: AtomicUsize,
    entered: AtomicBool,
    polls: AtomicUsize,
    dropped: AtomicBool,
    waiter: Mutex<Option<std::task::Waker>>,
}

struct GatedIo {
    inner: VirtualTcpStream,
    gate: Arc<WriteGate>,
}

impl Drop for GatedIo {
    fn drop(&mut self) {
        self.gate.dropped.store(true, Ordering::Release);
    }
}

impl AsyncRead for GatedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, bytes)
    }
}

impl AsyncWrite for GatedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.gate.blocked.load(Ordering::Acquire) {
            return Pin::new(&mut this.inner).poll_write(cx, bytes);
        }
        this.gate.entered.store(true, Ordering::Release);
        this.gate.polls.fetch_add(1, Ordering::AcqRel);
        let remaining = this.gate.remaining.load(Ordering::Acquire);
        if remaining == 0 {
            *this.gate.waiter.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let limit = bytes.len().min(remaining);
        let result = Pin::new(&mut this.inner).poll_write(cx, &bytes[..limit]);
        if let Poll::Ready(Ok(written)) = result {
            this.gate.remaining.fetch_sub(written, Ordering::AcqRel);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[test]
fn public_websocket_apps_cleanup_commits_view_cancel_before_stalled_native_retirement() {
    run_test(|| async {
        let cx = Cx::current().unwrap();
        for prefix in [0, 1] {
            for drop_cleanup in [false, true] {
                let (stream, server) = streams();
                let gate = Arc::new(WriteGate::default());
                let stream = GatedIo { inner: stream, gate: Arc::clone(&gate) };
                let mut peer = Peer::from_upgraded(server);
                let mut client = connect(&cx, stream, &mut peer, Options::default()).await;
                let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
                let mut host = client.mcp_apps_wire_host(transport, configuration()).unwrap();
                activate(&mut host, &mut view, &cx).await;
                enqueue(&mut view, &cx, "cancel-before-await", "tools/call", json!({"name": "slow"})).await;
                let mut drive = Box::pin(host.process_next(&cx));
                let catalog = request_while_pending(&mut drive, &mut peer, &cx).await;
                assert_eq!(catalog.id, Some(RequestId::Number(2)));
                assert_eq!(catalog.method, "tools/list");
                respond(&mut peer, &cx, 2, callable_tools(&["slow"])).await;
                let sent = request_while_pending(&mut drive, &mut peer, &cx).await;
                assert_eq!(sent.id, Some(RequestId::Number(3)));
                assert_eq!(sent.method, "tools/call");
                gate.remaining.store(prefix, Ordering::Release);
                gate.blocked.store(true, Ordering::Release);
                cancel_view(&mut view, &cx, "cancel-before-await").await;
                poll_fn(|task| {
                    assert!(drive.as_mut().poll(task).is_pending());
                    if gate.entered.load(Ordering::Acquire) {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                }).await;

                if drop_cleanup {
                    drop(drive);
                    // The native write was pending, but the synchronous View
                    // commitment already happened and survives this Drop.
                    assert_eq!(
                        host.admission.admit_control(
                            McpAppsBridgeDirection::ViewToHost,
                            McpAppsRoutedMethod::Cancelled,
                            Some(&json!({"requestId": "cancel-before-await"})),
                        ),
                        Err(McpAppsBridgeError::UnknownCorrelation),
                    );
                    assert!(host.policy.client.closed);
                    assert!(!gate.dropped.load(Ordering::Acquire));
                    let error = asupersync::time::timeout(
                        cx.now(), Duration::from_secs(1), host.process_next(&cx),
                    ).await.unwrap().unwrap_err();
                    assert!(matches!(error, McpAppsHostError::Core(_)));
                } else {
                    assert!(
                        asupersync::time::timeout(cx.now(), Duration::from_secs(1), drive)
                            .await.unwrap().is_err(),
                        "the native cancellation write has its own finite deadline",
                    );
                }
                assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Closed);
                assert!(gate.dropped.load(Ordering::Acquire), "both native halves are retired");
                assert!(!host.policy.client.mcp_apps_active());
                assert_eq!(host.policy.client.next_id, 4);
                assert_eq!(host.policy.client.retired_requests.len(), 1);
                let polls = gate.polls.load(Ordering::Acquire);
                assert!(host.process_next(&cx).await.is_err());
                assert_eq!(gate.polls.load(Ordering::Acquire), polls, "no second cancellation or Close");
                drop(host);
                assert!(client.closed);
                assert!(peer.recv(&cx).await.is_err(), "no complete cancellation or successor frame");
            }
        }
    });
}

#[cfg(feature = "tasks")]
mod tasks {
    use super::*;
    use crate::McpAppsServerTaskPolicy;

    fn task_snapshot(status: &str, creation: bool) -> Value {
        let mut value = json!({
            "resultType": if creation { "task" } else { "complete" },
            "taskId": "private-server-task", "status": status,
            "createdAt": "2026-07-28T12:00:00.000Z",
            "lastUpdatedAt": "2026-07-28T12:00:01.000Z",
            "ttlMs": null, "pollIntervalMs": 1, "statusMessage": "Host-private status"
        });
        match status {
            "input_required" => value["inputRequests"] = input_required("unused")["inputRequests"].clone(),
            "completed" => value["result"] = json!({"content": [{"type": "text", "text": "Task completed"}]}),
            _ => {}
        }
        value
    }

    struct TaskEffects {
        creation: bool,
        revoke_after: Option<usize>,
        delay: Duration,
        snapshots: Arc<Mutex<Vec<Value>>>,
        input: InputEffects,
    }

    impl TaskEffects {
        fn new() -> Self {
            Self {
                creation: true,
                revoke_after: None,
                delay: Duration::ZERO,
                snapshots: Arc::new(Mutex::new(Vec::new())),
                input: InputEffects::new(),
            }
        }
    }

    #[allow(clippy::unused_async_trait_impl, reason = "public async consent callbacks")]
    impl McpAppsWireHostEffects for TaskEffects {
        async fn server_task_policy(
            &mut self,
            cx: &Cx,
            cancellation: &McpRequestCancellation,
            params: &Value,
        ) -> Result<Option<McpAppsServerTaskPolicy>, McpAppsHostError> {
            super::super::super::wire_policy_checkpoint(cx, cancellation)?;
            if !self.creation || params["name"] != "job" {
                return Ok(None);
            }
            if !self.delay.is_zero() {
                asupersync::time::sleep(cx.now(), self.delay).await;
            }
            super::super::super::wire_policy_checkpoint(cx, cancellation)?;
            Ok(Some(McpAppsServerTaskPolicy::new(
                Duration::from_millis(10), 8, 64 * 1024,
            )?))
        }

        async fn approve_server_task(
            &mut self,
            cx: &Cx,
            cancellation: &McpRequestCancellation,
            params: &Value,
            task: &crate::FinalTask,
        ) -> Result<(), McpAppsHostError> {
            super::super::super::wire_policy_checkpoint(cx, cancellation)?;
            let mut snapshots = self.snapshots.lock().unwrap();
            snapshots.push(json!({
                "params": params, "taskId": task.base().task_id, "status": task.base().status
            }));
            if self.revoke_after.is_some_and(|limit| snapshots.len() > limit) {
                return Err(super::super::super::wire_policy_denied());
            }
            Ok(())
        }

        async fn resolve_server_input(
            &mut self,
            cx: &Cx,
            cancellation: &McpRequestCancellation,
            method: McpAppsRoutedMethod,
            params: &Value,
            required: &fastmcp_protocol::InputRequiredResult,
        ) -> Result<fastmcp_protocol::FinalInputResponses, McpAppsHostError> {
            self.input.resolve_server_input(cx, cancellation, method, params, required).await
        }
    }

    #[test]
    fn public_websocket_apps_task_composes_mrtr_host_input_update_and_terminal_result() {
        run_test(|| async {
            let cx = Cx::current().unwrap();
            let (stream, server) = streams();
            let mut peer = Peer::from_upgraded(server);
            let mut client = connect(&cx, stream, &mut peer, Options {
                tasks: true, ..Options::default()
            }).await;
            let effects = TaskEffects::new();
            let calls = Arc::clone(&effects.input.calls);
            let snapshots = Arc::clone(&effects.snapshots);
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let mut host = client.mcp_apps_wire_host(transport, configuration()).unwrap().with_effects(effects);
            activate(&mut host, &mut view, &cx).await;
            for (id, result) in [
                (2, callable_tools(&["job"])),
                (3, input_required("before-task-private-state")),
                (4, task_snapshot("working", true)),
                (5, task_snapshot("input_required", false)),
                (6, json!({"resultType": "complete"})),
                (7, task_snapshot("completed", false)),
            ] {
                respond(&mut peer, &cx, id, result).await;
            }
            let original = json!({"name": "job", "arguments": {"value": 7}});
            let response = request(&mut host, &mut view, &cx, "view-task", "tools/call", original.clone()).await;
            assert_eq!(response["result"], json!({"content": [{"type": "text", "text": "Task completed"}]}));
            let encoded = response.to_string();
            for private in ["private-server-task", "before-task-private-state", "inputResponses", "Host-private"] {
                assert!(!encoded.contains(private), "Host-owned task state cannot cross the View bridge");
            }
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 2, "one MRTR round and one Task input round");
            assert!(calls.iter().all(|call| call["params"] == original));
            drop(calls);
            assert!(snapshots.lock().unwrap().iter().any(|entry| entry["status"] == "completed"));
            let catalog = next_request(&mut peer, &cx).await;
            assert_eq!(catalog.id, Some(RequestId::Number(2)));
            assert_eq!(catalog.method, "tools/list");
            assert!(catalog.params.unwrap()["_meta"][crate::FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"]
                .get(fastmcp_protocol::TASKS_EXTENSION).is_none());
            for (id, method) in [
                (3, "tools/call"), (4, "tools/call"), (5, "tasks/get"),
                (6, "tasks/update"), (7, "tasks/get"),
            ] {
                let request = next_request(&mut peer, &cx).await;
                assert_eq!(request.id, Some(RequestId::Number(id)));
                assert_eq!(request.method, method);
                let params = request.params.unwrap();
                assert!(params["_meta"][crate::FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"]
                    .get(fastmcp_protocol::TASKS_EXTENSION).is_some());
                assert!(!params.to_string().contains("view-task"));
                if id == 4 {
                    assert_eq!(params["requestState"], "before-task-private-state");
                    assert_eq!(params["inputResponses"], input_response());
                    assert_eq!(params["arguments"], json!({"value": 7}));
                }
                if method.starts_with("tasks/") {
                    assert_eq!(params["taskId"], "private-server-task");
                }
                if id == 6 {
                    assert_eq!(params["inputResponses"], input_response());
                }
            }
            respond(&mut peer, &cx, 8, callable_tools(&["ordinary"])).await;
            respond(&mut peer, &cx, 9, complete("ordinary")).await;
            let ordinary = request(&mut host, &mut view, &cx, "view-task", "tools/call", json!({"name": "ordinary"})).await;
            assert_eq!(ordinary["result"]["content"][0]["text"], "ordinary");
            assert_eq!(next_request(&mut peer, &cx).await.method, "tools/list");
            let ordinary = next_request(&mut peer, &cx).await;
            assert_eq!(ordinary.id, Some(RequestId::Number(9)));
            assert!(ordinary.params.unwrap()["_meta"][crate::FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"]
                .get(fastmcp_protocol::TASKS_EXTENSION).is_none());

            // The outermost effects owner replaces an earlier Task consent.
            let mut host = host.with_effects(());
            respond(&mut peer, &cx, 10, callable_tools(&["job"])).await;
            respond(&mut peer, &cx, 11, complete("new consent owner")).await;
            assert!(request(&mut host, &mut view, &cx, "view-task", "tools/call", original).await.get("result").is_some());
            assert_eq!(next_request(&mut peer, &cx).await.method, "tools/list");
            let replaced = next_request(&mut peer, &cx).await;
            assert_eq!(replaced.id, Some(RequestId::Number(11)));
            assert!(replaced.params.unwrap()["_meta"][crate::FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"]
                .get(fastmcp_protocol::TASKS_EXTENSION).is_none());
            drop(host);
            client.close(&cx).await.unwrap();
            assert!(peer.recv(&cx).await.is_err(), "no Task cancel or replay");
        });
    }

    #[test]
    fn public_websocket_apps_task_refuses_unowned_unapproved_and_reused_inputs() {
        run_test(|| async {
            let cx = Cx::current().unwrap();
            for case in [
                "not-advertised", "not-approved", "foreign-task", "changed-creation",
                "input-round", "missing-sampling", "revoked-consent", "input-reuse",
            ] {
                let (stream, server) = streams();
                let mut peer = Peer::from_upgraded(server);
                let mut client = connect(&cx, stream, &mut peer, Options {
                    tasks: case != "not-advertised",
                    sampling: case != "missing-sampling",
                    ..Options::default()
                }).await;
                let mut effects = TaskEffects::new();
                if case == "not-approved" { effects.creation = false; }
                if case == "revoked-consent" { effects.revoke_after = Some(1); }
                if case == "input-round" {
                    effects.input.responses = json!({"other-round": input_response()["sample"]});
                }
                let calls = Arc::clone(&effects.input.calls);
                let (results, methods): (Vec<Value>, Vec<&str>) = match case {
                    "not-advertised" => (vec![], vec![]),
                    "not-approved" | "revoked-consent" => (
                        vec![task_snapshot("working", true)], vec!["tools/call"],
                    ),
                    "foreign-task" | "changed-creation" => {
                        let mut terminal = task_snapshot("completed", false);
                        if case == "foreign-task" {
                            terminal["taskId"] = json!("another-views-task");
                        } else {
                            terminal["createdAt"] = json!("2026-07-28T11:00:00.000Z");
                        }
                        (vec![task_snapshot("working", true), terminal], vec!["tools/call", "tasks/get"])
                    }
                    "input-reuse" => {
                        let mut reused = task_snapshot("input_required", false);
                        reused["inputRequests"]["sample"]["params"]["maxTokens"] = json!(64);
                        (
                            vec![task_snapshot("input_required", true), json!({"resultType": "complete"}), reused],
                            vec!["tools/call", "tasks/update", "tasks/get"],
                        )
                    }
                    _ => (vec![task_snapshot("input_required", true)], vec!["tools/call"]),
                };
                respond(&mut peer, &cx, 2, callable_tools(&["job"])).await;
                for (offset, result) in results.into_iter().enumerate() {
                    respond(&mut peer, &cx, i64::try_from(offset).unwrap() + 3, result).await;
                }
                let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
                let mut host = client.mcp_apps_wire_host(transport, configuration()).unwrap().with_effects(effects);
                activate(&mut host, &mut view, &cx).await;
                enqueue(&mut view, &cx, "refused", "tools/call", json!({"name": "job"})).await;
                let disposition = host.process_next(&cx).await;
                assert_eq!(disposition.is_err(), case == "foreign-task", "{case}");
                assert!(view_response(&mut view, &cx).await.get("error").is_some(), "{case}");
                assert_eq!(
                    calls.lock().unwrap().len(),
                    usize::from(matches!(case, "input-round" | "input-reuse")),
                    "{case}",
                );
                let catalog = next_request(&mut peer, &cx).await;
                assert_eq!(catalog.id, Some(RequestId::Number(2)));
                assert_eq!(catalog.method, "tools/list");
                for (offset, method) in methods.iter().enumerate() {
                    let request = next_request(&mut peer, &cx).await;
                    assert_eq!(request.id, Some(RequestId::Number(i64::try_from(offset).unwrap() + 3)));
                    assert_eq!(request.method.as_str(), *method);
                    if case == "not-approved" {
                        assert!(request.params.unwrap()["_meta"][crate::FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"]
                            .get(fastmcp_protocol::TASKS_EXTENSION).is_none());
                    }
                }
                if case == "foreign-task" {
                    assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Closed);
                    drop(host);
                    assert!(!client.mcp_apps_active());
                    assert!(peer.recv(&cx).await.is_err(), "foreign identity fences the connection");
                    continue;
                }
                let next_id = i64::try_from(methods.len()).unwrap() + 4;
                respond(&mut peer, &cx, next_id - 1, callable_tools(&["healthy"])).await;
                respond(&mut peer, &cx, next_id, complete("healthy")).await;
                assert!(request(&mut host, &mut view, &cx, "refused", "tools/call", json!({"name": "healthy"})).await.get("result").is_some());
                assert_eq!(next_request(&mut peer, &cx).await.method, "tools/list");
                let healthy = next_request(&mut peer, &cx).await;
                assert_eq!(healthy.id, Some(RequestId::Number(next_id)));
                assert_eq!(healthy.method, "tools/call", "no unauthorized Task update, read, cancel or replay");
                let params = healthy.params.unwrap();
                assert_eq!(params["name"], "healthy");
                assert!(params.get("taskId").is_none());
                assert!(params.get("inputResponses").is_none());
                drop(host);
                client.close(&cx).await.unwrap();
                assert!(peer.recv(&cx).await.is_err());
            }
        });
    }

    #[test]
    fn public_websocket_apps_original_deadline_bounds_pending_task_get_and_update() {
        run_test(|| async {
            let cx = Cx::current().unwrap();
            for method in ["tasks/get", "tasks/update"] {
                let (stream, server) = streams();
                let mut peer = Peer::from_upgraded(server);
                let mut client = connect(&cx, stream, &mut peer, Options {
                    tasks: true,
                    timeout: RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(1)).unwrap(),
                    ..Options::default()
                }).await;
                let mut effects = TaskEffects::new();
                // Spend part of the one Apps operation budget before its
                // tool RPC. A new per-RPC budget must not replace it.
                effects.delay = Duration::from_millis(700);
                let initial = if method == "tasks/get" { "working" } else { "input_required" };
                respond(&mut peer, &cx, 2, callable_tools(&["job"])).await;
                respond(&mut peer, &cx, 3, task_snapshot(initial, true)).await;
                let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
                let mut host = client.mcp_apps_wire_host(transport, configuration()).unwrap().with_effects(effects);
                activate(&mut host, &mut view, &cx).await;
                enqueue(&mut view, &cx, "bounded-task", "tools/call", json!({"name": "job"})).await;
                let mut drive = Box::pin(host.process_next(&cx));
                assert_eq!(request_while_pending(&mut drive, &mut peer, &cx).await.method, "tools/list");
                assert_eq!(request_while_pending(&mut drive, &mut peer, &cx).await.method, "tools/call");
                let held = request_while_pending(&mut drive, &mut peer, &cx).await;
                assert_eq!(held.method, method);
                assert_eq!(held.id, Some(RequestId::Number(4)));

                // No response or View cancellation wakes this held request.
                // Its own RPC timeout is 1 s; the original operation has only
                // about 300 ms left and must settle within this shorter bound.
                asupersync::time::timeout(cx.now(), Duration::from_millis(500), drive)
                    .await.expect("original Apps deadline owns the held Task RPC")
                    .unwrap();
                assert!(view_response(&mut view, &cx).await.get("error").is_some());
                let control = next_request(&mut peer, &cx).await;
                assert_eq!(control.method, "notifications/cancelled");
                assert_eq!(control.params.unwrap()["requestId"], 4);
                assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);

                respond(&mut peer, &cx, 4, if method == "tasks/get" {
                    task_snapshot("completed", false)
                } else {
                    json!({"resultType": "complete"})
                }).await;
                respond(&mut peer, &cx, 5, callable_tools(&["healthy"])).await;
                respond(&mut peer, &cx, 6, complete("after deadline")).await;
                let response = request(&mut host, &mut view, &cx, "bounded-task", "tools/call", json!({"name": "healthy"})).await;
                assert_eq!(response["result"]["content"][0]["text"], "after deadline");
                assert_eq!(next_request(&mut peer, &cx).await.method, "tools/list");
                let healthy = next_request(&mut peer, &cx).await;
                assert_eq!(healthy.method, "tools/call", "observation cancellation never cancels the remote Task");
                assert_eq!(healthy.id, Some(RequestId::Number(6)));
                drop(host);
                client.close(&cx).await.unwrap();
                assert!(peer.recv(&cx).await.is_err());
            }
        });
    }
}

#[test]
fn public_websocket_apps_catalog_deadline_bounds_an_uncommitted_native_send() {
    run_test(|| async {
        let cx = Cx::current().unwrap();
        for method in ["resources/list", "resources/templates/list", "prompts/list"] {
            for prefix in [0, 1] {
                let (stream, server) = streams();
                let gate = Arc::new(WriteGate::default());
                let stream = GatedIo { inner: stream, gate: Arc::clone(&gate) };
                let mut peer = Peer::from_upgraded(server);
                let mut client = connect(&cx, stream, &mut peer, Options {
                    timeout: RequestTimeoutPolicy::new(
                        Duration::from_secs(2), Duration::from_millis(50),
                    ).unwrap(),
                    ..Options::default()
                }).await;
                let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
                let mut host = client.mcp_apps_wire_host(transport, configuration()).unwrap();
                host.bind_server_catalogs(
                    McpAppsCatalogBinding {
                        view_id: "bounded-view".into(), resource_uri: "ui://bounded".into(),
                        origin: "https://view.example".into(), principal_id: "owner".into(),
                        server_id: "peer".into(), revision: "one".into(),
                    },
                    true,
                ).unwrap();
                activate(&mut host, &mut view, &cx).await;
                gate.remaining.store(prefix, Ordering::Release);
                gate.blocked.store(true, Ordering::Release);
                enqueue(&mut view, &cx, "bounded-list", method, json!({})).await;
                let error = asupersync::time::timeout(
                    cx.now(), Duration::from_secs(1), host.process_next(&cx),
                ).await.expect("the short client budget must bound allocation and send")
                    .unwrap_err();
                assert!(matches!(error, McpAppsHostError::Core(_)));
                assert!(gate.entered.load(Ordering::Acquire), "the admitted list reached native send");
                assert!(gate.dropped.load(Ordering::Acquire), "the incomplete send retires both halves");
                assert!(view_response(&mut view, &cx).await.get("error").is_some());
                assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Closed);
                assert_eq!(host.policy.client.next_id, 3);
                assert!(host.policy.client.retired_requests.is_empty(),
                    "an incomplete request cannot authorize a cancellation frame");
                drop(host);
                assert!(peer.recv(&cx).await.is_err(), "no completed list, cancellation or successor RPC");
            }
        }
    });
}
