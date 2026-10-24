//! Public native stdio serving over real Unix pipes, with no blocking workers.
//! These are implementation regressions, not aggregate conformance evidence.

#![cfg(unix)]
#![forbid(unsafe_code)]

use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::runtime::{RuntimeBuilder, TaskHandle, reactor::create_reactor};
use asupersync::sync::Notify;
use asupersync::{Cx, Outcome};
use fastmcp_core::{McpContext, McpOutcome, McpResult};
use fastmcp_protocol::protocol_policy::ProtocolPolicy;
use fastmcp_protocol::{
    CompleteResult, Content, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION,
    FINAL_PROTOCOL_VERSION_META_KEY, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId,
    ResultMeta, Tool,
};
use fastmcp_server::{FinalToolOutcome, Server, ToolExecutionMode, ToolHandler};
use fastmcp_transport::ReceivedTransportFrame;
use fastmcp_transport::{NativePipeReader, NativePipeWriter, create_native_pipe};

#[derive(Default)]
struct Probe {
    started: AtomicUsize,
    dropped: AtomicUsize,
    released: AtomicBool,
    output_blocked: AtomicBool,
    input_eof: AtomicBool,
    shutdown: AtomicBool,
    changed: Notify,
}

struct Active<'a>(&'a Probe);

impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.dropped.fetch_add(1, Ordering::AcqRel);
        self.0.changed.notify_waiters();
    }
}

struct PipeTool(Arc<Probe>);

impl ToolHandler for PipeTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "pipe_probe".to_owned(),
            description: None,
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "hold": {"type": "boolean"},
                    "value": {"type": "string"},
                    "repeat": {"type": "integer", "minimum": 1, "maximum": 131072},
                },
                "required": ["hold", "value"],
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

    fn call(&self, _: &McpContext, _: serde_json::Value) -> McpResult<Vec<Content>> {
        panic!("native serving must invoke the declared async final hook")
    }

    fn call_final_outcome_async<'a>(
        &'a self,
        _: &'a McpContext,
        arguments: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = McpOutcome<FinalToolOutcome>> + Send + 'a>> {
        Box::pin(async move {
            let _active = Active(&self.0);
            self.0.started.fetch_add(1, Ordering::AcqRel);
            self.0.changed.notify_waiters();
            if arguments["hold"] == true {
                self.0
                    .changed
                    .wait_until(|| self.0.released.load(Ordering::Acquire))
                    .await;
            }
            let repeat = usize::try_from(arguments["repeat"].as_u64().unwrap_or(1)).unwrap();
            let text = arguments["value"].as_str().unwrap().repeat(repeat);
            let payload = serde_json::from_value(serde_json::json!({
                "content": [{"type": "text", "text": text}],
                "isError": false,
            }))
            .expect("the runtime-selected text is a final tool payload");
            // `ResultMeta` has no `Default`; `empty()` is its constructor.
            Outcome::Ok(FinalToolOutcome::Complete(CompleteResult::new(
                payload,
                ResultMeta::empty(),
            )))
        })
    }
}

struct ObservedReader {
    pipe: NativePipeReader,
    probe: Arc<Probe>,
}

impl AsyncRead for ObservedReader {
    fn poll_read(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = output.filled().len();
        let had_capacity = output.remaining() > 0;
        let result = Pin::new(&mut this.pipe).poll_read(task, output);
        if had_capacity && matches!(result, Poll::Ready(Ok(()))) && output.filled().len() == before
        {
            this.probe.input_eof.store(true, Ordering::Release);
            this.probe.changed.notify_waiters();
        }
        result
    }
}

struct ObservedWriter {
    pipe: NativePipeWriter,
    probe: Arc<Probe>,
}

impl AsyncWrite for ObservedWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.pipe).poll_write(task, bytes);
        if result.is_pending() {
            this.probe.output_blocked.store(true, Ordering::Release);
            this.probe.changed.notify_waiters();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().pipe).poll_flush(task)
    }

    fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().pipe).poll_shutdown(task)
    }
}

// The peer owns the two OS pipe directions independently. In particular,
// closing ingress must not locally close the peer's response reader, which
// would hide whether the server actually drained its accepted responses.
struct Peer {
    input: NativePipeReader,
    output: NativePipeWriter,
    buffered: Vec<u8>,
}

impl Peer {
    async fn send(&mut self, message: &JsonRpcMessage) {
        let mut frame = serde_json::to_vec(message).unwrap();
        frame.push(b'\n');
        let mut remaining = frame.as_slice();
        while !remaining.is_empty() {
            let written = poll_fn(|task| Pin::new(&mut self.output).poll_write(task, remaining))
                .await
                .unwrap();
            assert!(written > 0, "pipe writer must make progress");
            remaining = &remaining[written..];
        }
    }

    async fn receive(&mut self) -> Option<JsonRpcMessage> {
        loop {
            if let Some(end) = self.buffered.iter().position(|byte| *byte == b'\n') {
                let mut frame: Vec<u8> = self.buffered.drain(..=end).collect();
                assert_eq!(frame.pop(), Some(b'\n'));
                return Some(
                    ReceivedTransportFrame::admit(frame)
                        .expect("server output must pass source-preserving frame admission")
                        .into_message(),
                );
            }
            let mut bytes = [0_u8; 8192];
            let count = poll_fn(|task| {
                let mut output = ReadBuf::new(&mut bytes);
                Pin::new(&mut self.input)
                    .poll_read(task, &mut output)
                    .map(|result| result.map(|()| output.filled().len()))
            })
            .await
            .unwrap();
            if count == 0 {
                assert!(
                    self.buffered.is_empty(),
                    "server closed after a partial frame"
                );
                return None;
            }
            assert!(self.buffered.len() + count <= 2 * 1024 * 1024);
            self.buffered.extend_from_slice(&bytes[..count]);
        }
    }

    async fn response(&mut self, id: i64) -> JsonRpcResponse {
        let Some(JsonRpcMessage::Response(response)) = self.receive().await else {
            panic!("expected response {id}, not EOF or a notification");
        };
        assert_eq!(response.id, Some(RequestId::Number(id)));
        assert!(response.error.is_none(), "{response:?}");
        response
    }

    async fn half_close(&mut self) {
        poll_fn(|task| Pin::new(&mut self.output).poll_shutdown(task))
            .await
            .unwrap();
    }
}

fn request(id: i64, method: &str, mut params: serde_json::Value) -> JsonRpcMessage {
    params["_meta"] = serde_json::json!({
        FINAL_PROTOCOL_VERSION_META_KEY: FINAL_PROTOCOL_VERSION,
        FINAL_CLIENT_CAPABILITIES_META_KEY: {},
    });
    JsonRpcMessage::Request(JsonRpcRequest::new(method, Some(params), id))
}

fn call(id: i64, hold: bool, value: &str, repeat: usize) -> JsonRpcMessage {
    request(
        id,
        "tools/call",
        serde_json::json!({
            "name": "pipe_probe",
            "arguments": {"hold": hold, "value": value, "repeat": repeat},
        }),
    )
}

fn cancel(id: i64) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest::notification(
        "notifications/cancelled",
        Some(serde_json::json!({"requestId": id})),
    ))
}

fn connect(cx: &Cx, probe: &Arc<Probe>) -> (Peer, TaskHandle<McpResult<()>>) {
    let (server_input, peer_output) = create_native_pipe(cx).unwrap();
    let (peer_input, server_output) = create_native_pipe(cx).unwrap();
    let shutdown = Arc::clone(probe);
    let server = Server::new("native-pipe-server", "1")
        .protocol_policy(ProtocolPolicy::ModernOnly)
        .unwrap()
        .tool(PipeTool(Arc::clone(probe)))
        .on_shutdown(move || {
            assert_eq!(
                shutdown.started.load(Ordering::Acquire),
                shutdown.dropped.load(Ordering::Acquire),
                "shutdown must not run over an active request future",
            );
            shutdown.shutdown.store(true, Ordering::Release);
        })
        .build();
    let reader = ObservedReader {
        pipe: server_input,
        probe: Arc::clone(probe),
    };
    let writer = ObservedWriter {
        pipe: server_output,
        probe: Arc::clone(probe),
    };
    let serving = cx
        .spawn(
            move |server_cx| async move { server.serve_stdio_io(&server_cx, reader, writer).await },
        )
        .unwrap();
    (
        Peer {
            input: peer_input,
            output: peer_output,
            buffered: Vec::new(),
        },
        serving,
    )
}

fn run<F, Fut>(test: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(8), test(cx.clone()))
            .await
            .expect("native pipe serving must make progress on one runtime thread");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

async fn stop(cx: &Cx, mut peer: Peer, mut serving: TaskHandle<McpResult<()>>, probe: &Probe) {
    peer.half_close().await;
    assert!(
        peer.receive().await.is_none(),
        "unexpected late response during drain"
    );
    serving.join(cx).await.unwrap().unwrap();
    assert!(probe.shutdown.load(Ordering::Acquire));
}

#[test]
fn real_pipe_server_multiplexes_pending_and_ready_requests_without_blocking_workers() {
    run(|cx| async move {
        let probe = Arc::new(Probe::default());
        let (mut peer, serving) = connect(&cx, &probe);
        peer.send(&request(1, "server/discover", serde_json::json!({})))
            .await;
        peer.response(1).await;
        peer.send(&call(2, true, "slow", 1)).await;
        probe
            .changed
            .wait_until(|| probe.started.load(Ordering::Acquire) == 1)
            .await;
        peer.send(&call(3, false, "fast", 1)).await;
        let fast = peer.response(3).await.result.unwrap();
        assert_eq!(fast["content"][0]["text"], "fast");
        assert_eq!(probe.dropped.load(Ordering::Acquire), 1);
        probe.released.store(true, Ordering::Release);
        probe.changed.notify_waiters();
        let slow = peer.response(2).await.result.unwrap();
        assert_eq!(slow["content"][0]["text"], "slow");
        stop(&cx, peer, serving, &probe).await;
        assert_eq!(probe.dropped.load(Ordering::Acquire), 2);
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn real_pipe_server_cancellation_targets_only_the_matching_pending_request() {
    for matching in [true, false] {
        run(|cx| async move {
            let probe = Arc::new(Probe::default());
            let (mut peer, serving) = connect(&cx, &probe);
            peer.send(&call(10, true, "held", 1)).await;
            probe
                .changed
                .wait_until(|| probe.started.load(Ordering::Acquire) == 1)
                .await;
            // Positive and negative differ only in this wire cancellation ID.
            peer.send(&cancel(if matching { 10 } else { 999 })).await;
            peer.send(&call(11, false, "sibling", 1)).await;
            peer.response(11).await;
            if matching {
                probe
                    .changed
                    .wait_until(|| probe.dropped.load(Ordering::Acquire) == 2)
                    .await;
            } else {
                assert_eq!(probe.dropped.load(Ordering::Acquire), 1);
            }
            probe.released.store(true, Ordering::Release);
            probe.changed.notify_waiters();
            if !matching {
                assert_eq!(
                    peer.response(10).await.result.unwrap()["content"][0]["text"],
                    "held"
                );
            }
            // For the matching ID, both the next-response check above and
            // the EOF check below reject a leaked cancelled result.
            stop(&cx, peer, serving, &probe).await;
            assert_eq!(probe.dropped.load(Ordering::Acquire), 2);
        });
    }
}

#[test]
fn real_pipe_server_drains_a_result_created_after_observed_input_eof() {
    run(|cx| async move {
        let probe = Arc::new(Probe::default());
        let (mut peer, mut serving) = connect(&cx, &probe);
        peer.send(&call(20, true, "after-half-close", 1)).await;
        probe
            .changed
            .wait_until(|| probe.started.load(Ordering::Acquire) == 1)
            .await;
        peer.half_close().await;
        probe
            .changed
            .wait_until(|| probe.input_eof.load(Ordering::Acquire))
            .await;
        assert_eq!(probe.dropped.load(Ordering::Acquire), 0);
        assert!(!probe.shutdown.load(Ordering::Acquire));
        probe.released.store(true, Ordering::Release);
        probe.changed.notify_waiters();
        assert_eq!(
            peer.response(20).await.result.unwrap()["content"][0]["text"],
            "after-half-close",
        );
        assert!(peer.receive().await.is_none());
        serving.join(&cx).await.unwrap().unwrap();
        assert!(probe.shutdown.load(Ordering::Acquire));
    });
}

#[test]
fn real_pipe_server_routes_cancellation_while_response_output_is_backpressured() {
    run(|cx| async move {
        let probe = Arc::new(Probe::default());
        let (mut peer, serving) = connect(&cx, &probe);
        peer.send(&call(30, false, "abcdefgh", 131072)).await;
        // This barrier observes a real Pending pipe write, not just handler
        // completion or a sleep that hopes output has filled by now.
        probe
            .changed
            .wait_until(|| probe.output_blocked.load(Ordering::Acquire))
            .await;
        peer.send(&call(31, true, "cancel-behind-output", 1)).await;
        probe
            .changed
            .wait_until(|| probe.started.load(Ordering::Acquire) == 2)
            .await;
        peer.send(&cancel(31)).await;
        probe
            .changed
            .wait_until(|| probe.dropped.load(Ordering::Acquire) == 2)
            .await;
        assert!(!probe.shutdown.load(Ordering::Acquire));
        // No response bytes have been drained by the peer until this point.
        let large = peer.response(30).await.result.unwrap();
        assert_eq!(
            large["content"][0]["text"].as_str().unwrap(),
            "abcdefgh".repeat(131072)
        );
        peer.send(&call(32, false, "still-live", 1)).await;
        assert_eq!(
            peer.response(32).await.result.unwrap()["content"][0]["text"],
            "still-live"
        );
        stop(&cx, peer, serving, &probe).await;
        assert_eq!(probe.dropped.load(Ordering::Acquire), 3);
    });
}

// Core subscription proxying must compile and run with `proxy` alone. The
// upstreams deliberately have no Tasks service even when `tasks` is enabled.
#[cfg(feature = "proxy")]
mod core_proxy_subscriptions {
    use super::*;
    use std::sync::Mutex;

    use fastmcp_client::ClientProtocolPlan;
    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_protocol::{
        ClientCapabilities, ClientInfo, FINAL_SUBSCRIPTION_ID_META_KEY, Resource, ResourceContent,
        SubscriptionFilter,
    };
    use fastmcp_server::{DuplicateBehavior, HttpServerShutdown, ProxyClient, ResourceHandler};

    struct WatchedResource(String);

    impl ResourceHandler for WatchedResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: self.0.clone(),
                name: self.0.clone(),
                description: None,
                mime_type: Some("text/plain".to_owned()),
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn read(&self, _: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![ResourceContent {
                uri: self.0.clone(),
                mime_type: Some("text/plain".to_owned()),
                text: Some("watched".to_owned()),
                blob: None,
            }])
        }
    }

    struct PublishTool;

    impl ToolHandler for PublishTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "publish".to_owned(),
                description: None,
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "uri": {"type": "string"},
                        "catalog": {"enum": ["tools"]},
                    },
                    "oneOf": [{"required": ["uri"]}, {"required": ["catalog"]}],
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

        fn call(&self, _: &McpContext, _: serde_json::Value) -> McpResult<Vec<Content>> {
            panic!("the real HTTP upstream must use the async tool hook")
        }

        fn call_final_outcome_async<'a>(
            &'a self,
            ctx: &'a McpContext,
            arguments: serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = McpOutcome<FinalToolOutcome>> + Send + 'a>> {
            Box::pin(async move {
                let accepted = if arguments["catalog"] == "tools" {
                    ctx.disable_tool("pipe_probe")
                } else {
                    ctx.notify_resource_updated(arguments["uri"].as_str().unwrap())
                };
                let payload = serde_json::from_value(serde_json::json!({
                    "content": [{"type": "text", "text": accepted.to_string()}],
                    "isError": false,
                }))
                .unwrap();
                Outcome::Ok(FinalToolOutcome::Complete(CompleteResult::new(
                    payload,
                    ResultMeta::empty(),
                )))
            })
        }
    }

    struct Upstream {
        proxy: ProxyClient,
        uris: [String; 2],
        owner: Arc<Mutex<Option<Cx>>>,
        serving: TaskHandle<McpResult<HttpServerShutdown>>,
    }

    impl Upstream {
        async fn open(cx: &Cx, name: &str) -> Self {
            let uris = [format!("test://{name}/a"), format!("test://{name}/b")];
            let server = Server::new(name, "1")
                .protocol_policy(ProtocolPolicy::ModernOnly)
                .unwrap()
                .resource(WatchedResource(uris[0].clone()))
                .resource(WatchedResource(uris[1].clone()))
                .tool(PublishTool)
                .tool(PipeTool(Arc::new(Probe::default())))
                .build();
            let bound = server.bind_http(cx, "127.0.0.1:0").await.unwrap();
            let target =
                CanonicalHttpUrl::parse(&format!("http://{}/mcp", bound.local_addr().unwrap()))
                    .unwrap();
            let owner = Arc::new(Mutex::new(None));
            let running_owner = Arc::clone(&owner);
            let serving = cx
                .spawn(move |server_cx| async move {
                    *running_owner.lock().unwrap() = Some(server_cx.clone());
                    bound.serve(&server_cx).await
                })
                .unwrap();
            let plan = ClientProtocolPlan::http(
                ProtocolPolicy::ModernOnly,
                Some(target),
                None,
                None,
                format!("credential:{name}"),
                format!("security:{name}"),
                "modern-http".to_owned(),
                0,
                1,
                0,
            )
            .unwrap();
            let proxy = ProxyClient::upstream_binding_registry()
                .connect_http_with_protocol_plan(
                    cx,
                    name,
                    &format!("native-http:{name}"),
                    1,
                    plan,
                    ClientInfo {
                        name: "core-proxy-native-pipe-test".to_owned(),
                        version: "1".to_owned(),
                    },
                    ClientCapabilities::default(),
                )
                .await
                .unwrap();
            Self {
                proxy,
                uris,
                owner,
                serving,
            }
        }

        async fn gateway(&self, cx: &Cx, prefix: &str) -> Server {
            let catalog = self.proxy.catalog_typed_with_cx(cx).await.unwrap();
            Server::new("core-proxy-gateway", "1")
                .protocol_policy(ProtocolPolicy::ModernOnly)
                .unwrap()
                .as_proxy_typed(prefix, self.proxy.clone(), catalog)
                .unwrap()
                .build()
        }

        async fn stop(mut self, cx: &Cx) {
            self.owner
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .set_cancel_requested(true);
            match self.serving.join(cx).await.unwrap().unwrap() {
                HttpServerShutdown::Quiescent => {}
                HttpServerShutdown::Nonquiescent(pending) => {
                    pending.settle(cx).await.unwrap();
                    panic!("core subscription cleanup left an HTTP child running");
                }
            }
            assert!(
                cx.checkpoint().is_ok(),
                "stopping one upstream cancelled its caller"
            );
        }
    }

    fn connect_gateway(cx: &Cx, server: Server) -> (Peer, TaskHandle<McpResult<()>>) {
        let (server_input, peer_output) = create_native_pipe(cx).unwrap();
        let (peer_input, server_output) = create_native_pipe(cx).unwrap();
        let serving = cx
            .spawn(move |server_cx| async move {
                server
                    .serve_stdio_io(&server_cx, server_input, server_output)
                    .await
            })
            .unwrap();
        (
            Peer {
                input: peer_input,
                output: peer_output,
                buffered: Vec::new(),
            },
            serving,
        )
    }

    async fn stop_gateway(cx: &Cx, mut peer: Peer, mut serving: TaskHandle<McpResult<()>>) {
        peer.half_close().await;
        assert!(
            peer.receive().await.is_none(),
            "a cancelled listener leaked a late frame"
        );
        serving.join(cx).await.unwrap().unwrap();
    }

    fn subscription_id(event: &JsonRpcRequest) -> i64 {
        assert!(
            event.id.is_none(),
            "subscription delivery must be a notification"
        );
        event.params.as_ref().unwrap()["_meta"][FINAL_SUBSCRIPTION_ID_META_KEY]
            .as_i64()
            .expect("the upstream ID must be replaced with the downstream numeric ID")
    }

    async fn listen(peer: &mut Peer, id: i64, filter: SubscriptionFilter) {
        let filter = serde_json::to_value(filter).unwrap();
        peer.send(&request(
            id,
            "subscriptions/listen",
            serde_json::json!({"notifications": filter}),
        ))
        .await;
        let Some(JsonRpcMessage::Request(ack)) = peer.receive().await else {
            panic!("a live upstream must produce a downstream subscription acknowledgement");
        };
        assert_eq!(ack.method, "notifications/subscriptions/acknowledged");
        assert_eq!(subscription_id(&ack), id);
        assert_eq!(ack.params.unwrap()["notifications"], filter);
    }

    async fn publish(
        peer: &mut Peer,
        id: i64,
        prefix: &str,
        arguments: serde_json::Value,
        event_count: usize,
    ) -> (bool, Vec<JsonRpcRequest>) {
        let name = if prefix.is_empty() {
            "publish".to_owned()
        } else {
            format!("{prefix}/publish")
        };
        peer.send(&request(
            id,
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
        ))
        .await;
        let mut result = None;
        let mut events = Vec::new();
        while result.is_none() || events.len() < event_count {
            match peer
                .receive()
                .await
                .expect("gateway closed during a live subscription")
            {
                JsonRpcMessage::Request(event) => events.push(event),
                JsonRpcMessage::Response(response) => {
                    assert_eq!(response.id, Some(RequestId::Number(id)));
                    assert!(response.error.is_none(), "{response:?}");
                    assert!(
                        result.is_none(),
                        "ordinary requests must complete only once"
                    );
                    result = Some(
                        response.result.unwrap()["content"][0]["text"]
                            .as_str()
                            .unwrap()
                            .parse::<bool>()
                            .unwrap(),
                    );
                }
            }
        }
        assert_eq!(
            events.len(),
            event_count,
            "a relay broadcast outside its owning listener"
        );
        (result.unwrap(), events)
    }

    async fn assert_no_extra_frames(cx: &Cx, peer: &mut Peer) {
        // Each positive delivery is awaited above. This bounded negative
        // observation catches duplicate retagging and events to cancelled IDs.
        assert!(
            asupersync::time::timeout(cx.now(), Duration::from_millis(40), peer.receive())
                .await
                .is_err(),
            "a filtered or cancelled subscription received an extra frame",
        );
    }

    fn assert_resource_events(events: &[JsonRpcRequest], uri: &str, ids: &[i64]) {
        let mut actual = Vec::new();
        for event in events {
            assert_eq!(event.method, "notifications/resources/updated");
            assert_eq!(event.params.as_ref().unwrap()["uri"], uri);
            actual.push(subscription_id(event));
        }
        actual.sort_unstable();
        let mut expected = ids.to_vec();
        expected.sort_unstable();
        assert_eq!(actual, expected);
    }

    async fn assert_upstream_released(cx: &Cx, peer: &mut Peer, prefix: &str, uri: &str) {
        // A real HTTP peer may observe a closed SSE body on its next write.
        // Repeated public tool calls drive that observation without reading a
        // private relay table or manufacturing a teardown acknowledgement.
        for id in 900..920 {
            let (delivered, events) =
                publish(peer, id, prefix, serde_json::json!({"uri": uri}), 0).await;
            assert!(events.is_empty());
            if !delivered {
                assert_no_extra_frames(cx, peer).await;
                return;
            }
            asupersync::runtime::yield_now().await;
        }
        panic!("cancelled downstream listeners retained an upstream subscription");
    }

    #[test]
    fn core_proxy_resource_events_are_retagged_once_and_cancellation_is_listener_scoped() {
        run(|cx| async move {
            let upstream = Upstream::open(&cx, "core-subscriptions").await;
            let (mut peer, serving) = connect_gateway(&cx, upstream.gateway(&cx, "remote").await);
            let (delivered, _) = publish(
                &mut peer,
                100,
                "remote",
                serde_json::json!({"uri": upstream.uris[0]}),
                0,
            )
            .await;
            assert!(
                !delivered,
                "the negative control has no upstream listener yet"
            );
            listen(
                &mut peer,
                701,
                SubscriptionFilter {
                    resource_subscriptions: Some(vec![upstream.uris[0].clone()]),
                    ..SubscriptionFilter::default()
                },
            )
            .await;
            listen(
                &mut peer,
                702,
                SubscriptionFilter {
                    resource_subscriptions: Some(upstream.uris.to_vec()),
                    ..SubscriptionFilter::default()
                },
            )
            .await;

            peer.send(&cancel(799)).await;
            let (delivered, events) = publish(
                &mut peer,
                101,
                "remote",
                serde_json::json!({"uri": upstream.uris[0]}),
                2,
            )
            .await;
            assert!(
                delivered,
                "an unrelated cancellation ID must preserve both listeners"
            );
            assert_resource_events(&events, &upstream.uris[0], &[701, 702]);
            assert_no_extra_frames(&cx, &mut peer).await;
            let (delivered, events) = publish(
                &mut peer,
                102,
                "remote",
                serde_json::json!({"uri": upstream.uris[1]}),
                1,
            )
            .await;
            assert!(delivered);
            assert_resource_events(&events, &upstream.uris[1], &[702]);
            assert_no_extra_frames(&cx, &mut peer).await;

            peer.send(&cancel(701)).await;
            let (delivered, events) = publish(
                &mut peer,
                103,
                "remote",
                serde_json::json!({"uri": upstream.uris[0]}),
                1,
            )
            .await;
            assert!(
                delivered,
                "cancelling one listener must preserve its sibling"
            );
            assert_resource_events(&events, &upstream.uris[0], &[702]);
            assert_no_extra_frames(&cx, &mut peer).await;
            peer.send(&cancel(702)).await;
            assert_upstream_released(&cx, &mut peer, "remote", &upstream.uris[0]).await;
            stop_gateway(&cx, peer, serving).await;
            upstream.stop(&cx).await;
        });
    }

    #[test]
    fn core_proxy_tools_list_changed_reaches_only_the_opted_in_listener() {
        run(|cx| async move {
            let upstream = Upstream::open(&cx, "core-catalog").await;
            let (mut peer, serving) = connect_gateway(&cx, upstream.gateway(&cx, "remote").await);
            listen(
                &mut peer,
                711,
                SubscriptionFilter {
                    resource_subscriptions: Some(vec![upstream.uris[0].clone()]),
                    ..SubscriptionFilter::default()
                },
            )
            .await;
            listen(
                &mut peer,
                712,
                SubscriptionFilter {
                    tools_list_changed: Some(true),
                    ..SubscriptionFilter::default()
                },
            )
            .await;
            let (changed, events) = publish(
                &mut peer,
                110,
                "remote",
                serde_json::json!({"catalog": "tools"}),
                1,
            )
            .await;
            assert!(changed, "the real upstream tool must mutate its catalog");
            assert_eq!(events[0].method, "notifications/tools/list_changed");
            assert_eq!(subscription_id(&events[0]), 712);
            assert_no_extra_frames(&cx, &mut peer).await;
            peer.send(&cancel(712)).await;
            let (delivered, events) = publish(
                &mut peer,
                111,
                "remote",
                serde_json::json!({"uri": upstream.uris[0]}),
                1,
            )
            .await;
            assert!(delivered);
            assert_resource_events(&events, &upstream.uris[0], &[711]);
            peer.send(&cancel(711)).await;
            assert_upstream_released(&cx, &mut peer, "remote", &upstream.uris[0]).await;
            stop_gateway(&cx, peer, serving).await;
            upstream.stop(&cx).await;
        });
    }

    #[test]
    fn core_proxy_local_resource_ownership_excludes_stale_upstream_catalog_entries() {
        for behavior in [
            DuplicateBehavior::Ignore,
            DuplicateBehavior::Warn,
            DuplicateBehavior::Replace,
        ] {
            run(|cx| async move {
                let upstream = Upstream::open(&cx, "core-local-owner").await;
                let catalog = upstream.proxy.catalog_typed_with_cx(&cx).await.unwrap();
                let builder = Server::new("local-owner-gateway", "1")
                    .protocol_policy(ProtocolPolicy::ModernOnly)
                    .unwrap()
                    .on_duplicate(behavior)
                    .tool(PublishTool);
                let builder = if behavior == DuplicateBehavior::Replace {
                    builder
                        .as_proxy_typed("remote", upstream.proxy.clone(), catalog)
                        .unwrap()
                        .resource(WatchedResource(upstream.uris[0].clone()))
                } else {
                    builder
                        .resource(WatchedResource(upstream.uris[0].clone()))
                        .as_proxy_typed("remote", upstream.proxy.clone(), catalog)
                        .unwrap()
                };
                let (mut peer, serving) = connect_gateway(&cx, builder.build());
                listen(
                    &mut peer,
                    731,
                    SubscriptionFilter {
                        resource_subscriptions: Some(upstream.uris.to_vec()),
                        ..SubscriptionFilter::default()
                    },
                )
                .await;

                // The upstream advertised A before the local handler won its
                // registration. A historical catalog entry must not authorize
                // opening an upstream subscription for that locally owned URI.
                let (delivered, events) = publish(
                    &mut peer,
                    130,
                    "remote",
                    serde_json::json!({"uri": upstream.uris[0]}),
                    0,
                )
                .await;
                assert!(
                    !delivered,
                    "{behavior:?} left a stale upstream resource listener"
                );
                assert!(events.is_empty());
                assert_no_extra_frames(&cx, &mut peer).await;

                // Change only the publisher's origin: the same URI remains a
                // valid local subscription and must receive a local update.
                let (delivered, events) = publish(
                    &mut peer,
                    131,
                    "",
                    serde_json::json!({"uri": upstream.uris[0]}),
                    1,
                )
                .await;
                assert!(delivered);
                assert_resource_events(&events, &upstream.uris[0], &[731]);
                let (delivered, events) = publish(
                    &mut peer,
                    132,
                    "remote",
                    serde_json::json!({"uri": upstream.uris[1]}),
                    1,
                )
                .await;
                assert!(
                    delivered,
                    "local ownership of A must not disable upstream ownership of B"
                );
                assert_resource_events(&events, &upstream.uris[1], &[731]);
                assert_no_extra_frames(&cx, &mut peer).await;
                peer.send(&cancel(731)).await;
                assert_upstream_released(&cx, &mut peer, "remote", &upstream.uris[1]).await;
                stop_gateway(&cx, peer, serving).await;
                upstream.stop(&cx).await;
            });
        }
    }

    #[test]
    fn mounted_core_proxy_routes_forward_both_origins_without_idle_origin_starvation() {
        run(|cx| async move {
            let first = Upstream::open(&cx, "core-origin-first").await;
            let second = Upstream::open(&cx, "core-origin-second").await;
            let gateway = Server::new("mounted-core-gateway", "1")
                .protocol_policy(ProtocolPolicy::ModernOnly)
                .unwrap()
                .mount_preserving_resource_uris(first.gateway(&cx, "first").await, None)
                .mount_preserving_resource_uris(second.gateway(&cx, "second").await, None)
                .build();
            let (mut peer, serving) = connect_gateway(&cx, gateway);
            listen(
                &mut peer,
                721,
                SubscriptionFilter {
                    resource_subscriptions: Some(vec![
                        first.uris[0].clone(),
                        second.uris[0].clone(),
                    ]),
                    ..SubscriptionFilter::default()
                },
            )
            .await;
            listen(
                &mut peer,
                722,
                SubscriptionFilter {
                    resource_subscriptions: Some(vec![second.uris[1].clone()]),
                    ..SubscriptionFilter::default()
                },
            )
            .await;
            // Emit from the second mounted route while the first is idle.
            // Awaiting the first upstream's read would deadlock this delivery.
            let (delivered, events) = publish(
                &mut peer,
                120,
                "second",
                serde_json::json!({"uri": second.uris[0]}),
                1,
            )
            .await;
            assert!(delivered);
            assert_resource_events(&events, &second.uris[0], &[721]);
            let (delivered, events) = publish(
                &mut peer,
                121,
                "first",
                serde_json::json!({"uri": first.uris[0]}),
                1,
            )
            .await;
            assert!(delivered);
            assert_resource_events(&events, &first.uris[0], &[721]);
            let (delivered, events) = publish(
                &mut peer,
                122,
                "second",
                serde_json::json!({"uri": second.uris[1]}),
                1,
            )
            .await;
            assert!(delivered);
            assert_resource_events(&events, &second.uris[1], &[722]);
            assert_no_extra_frames(&cx, &mut peer).await;
            peer.send(&cancel(721)).await;
            assert_upstream_released(&cx, &mut peer, "first", &first.uris[0]).await;
            let (delivered, events) = publish(
                &mut peer,
                123,
                "second",
                serde_json::json!({"uri": second.uris[1]}),
                1,
            )
            .await;
            assert!(
                delivered,
                "one listener's two-route teardown cancelled an independent listener"
            );
            assert_resource_events(&events, &second.uris[1], &[722]);
            peer.send(&cancel(722)).await;
            assert_upstream_released(&cx, &mut peer, "second", &second.uris[1]).await;
            stop_gateway(&cx, peer, serving).await;
            first.stop(&cx).await;
            second.stop(&cx).await;
        });
    }
}
