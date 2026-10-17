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
        if had_capacity && matches!(result, Poll::Ready(Ok(()))) && output.filled().len() == before {
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
                assert!(self.buffered.is_empty(), "server closed after a partial frame");
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
    request(id, "tools/call", serde_json::json!({
        "name": "pipe_probe",
        "arguments": {"hold": hold, "value": value, "repeat": repeat},
    }))
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
    let reader = ObservedReader { pipe: server_input, probe: Arc::clone(probe) };
    let writer = ObservedWriter { pipe: server_output, probe: Arc::clone(probe) };
    let serving = cx
        .spawn(move |server_cx| async move {
            server.serve_stdio_io(&server_cx, reader, writer).await
        })
        .unwrap();
    (Peer { input: peer_input, output: peer_output, buffered: Vec::new() }, serving)
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
    assert!(peer.receive().await.is_none(), "unexpected late response during drain");
    serving.join(cx).await.unwrap().unwrap();
    assert!(probe.shutdown.load(Ordering::Acquire));
}

#[test]
fn real_pipe_server_multiplexes_pending_and_ready_requests_without_blocking_workers() {
    run(|cx| async move {
        let probe = Arc::new(Probe::default());
        let (mut peer, serving) = connect(&cx, &probe);
        peer.send(&request(1, "server/discover", serde_json::json!({}))).await;
        peer.response(1).await;
        peer.send(&call(2, true, "slow", 1)).await;
        probe.changed.wait_until(|| probe.started.load(Ordering::Acquire) == 1).await;
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
            probe.changed.wait_until(|| probe.started.load(Ordering::Acquire) == 1).await;
            // Positive and negative differ only in this wire cancellation ID.
            peer.send(&cancel(if matching { 10 } else { 999 })).await;
            peer.send(&call(11, false, "sibling", 1)).await;
            peer.response(11).await;
            if matching {
                probe.changed.wait_until(|| probe.dropped.load(Ordering::Acquire) == 2).await;
            } else {
                assert_eq!(probe.dropped.load(Ordering::Acquire), 1);
            }
            probe.released.store(true, Ordering::Release);
            probe.changed.notify_waiters();
            if !matching {
                assert_eq!(peer.response(10).await.result.unwrap()["content"][0]["text"], "held");
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
        probe.changed.wait_until(|| probe.started.load(Ordering::Acquire) == 1).await;
        peer.half_close().await;
        probe.changed.wait_until(|| probe.input_eof.load(Ordering::Acquire)).await;
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
        probe.changed.wait_until(|| probe.output_blocked.load(Ordering::Acquire)).await;
        peer.send(&call(31, true, "cancel-behind-output", 1)).await;
        probe.changed.wait_until(|| probe.started.load(Ordering::Acquire) == 2).await;
        peer.send(&cancel(31)).await;
        probe.changed.wait_until(|| probe.dropped.load(Ordering::Acquire) == 2).await;
        assert!(!probe.shutdown.load(Ordering::Acquire));
        // No response bytes have been drained by the peer until this point.
        let large = peer.response(30).await.result.unwrap();
        assert_eq!(large["content"][0]["text"].as_str().unwrap(), "abcdefgh".repeat(131072));
        peer.send(&call(32, false, "still-live", 1)).await;
        assert_eq!(peer.response(32).await.result.unwrap()["content"][0]["text"], "still-live");
        stop(&cx, peer, serving, &probe).await;
        assert_eq!(probe.dropped.load(Ordering::Acquire), 3);
    });
}
