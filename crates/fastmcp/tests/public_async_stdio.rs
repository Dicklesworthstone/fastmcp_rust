//! Real native-pipe round trips through the public, era-pinned facade APIs.
//!
//! The modern case also runs with `--no-default-features`. All handlers and
//! transport endpoints use one caller-owned runtime with no blocking pool.

#![cfg(unix)]
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_rust::{
    AsyncStdioTransport, Cx, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION_META_KEY,
    JsonRpcMessage, JsonRpcRequest, JsonValue, McpContext, McpResult, NativePipeReader,
    NativePipeWriter, RequestId, create_native_pipe, json, modern, tool,
};

type Peer = AsyncStdioTransport<NativePipeReader, NativePipeWriter>;

/// Echoes an argument after yielding to the caller's timer.
#[tool]
async fn facade_echo(ctx: &McpContext, value: String) -> McpResult<String> {
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
        reader: NativePipeReader,
        writer: NativePipeWriter,
        stopped: Arc<AtomicBool>,
    ) -> McpResult<()> {
        let shutdown = move || stopped.store(true, Ordering::Release);
        match self {
            Self::Modern => {
                modern::ServerBuilder::new("facade-native-stdio", "1.2.3")
                    .tool(FacadeEcho)
                    .on_shutdown(shutdown)
                    .build()
                    .serve_stdio_io(cx, reader, writer)
                    .await
            }
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Auto => {
                fastmcp_rust::auto::ServerBuilder::new("facade-native-stdio", "1.2.3")
                    .tool(FacadeEcho)
                    .on_shutdown(shutdown)
                    .build()
                    .serve_stdio_io(cx, reader, writer)
                    .await
            }
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Legacy => {
                fastmcp_rust::legacy_2024::ServerBuilder::new("facade-native-stdio", "1.2.3")
                    .tool(FacadeEcho)
                    .on_shutdown(shutdown)
                    .build()
                    .serve_stdio_io(cx, reader, writer)
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

    async fn open(self, cx: &Cx, peer: &mut Peer) {
        match self {
            Self::Modern => {
                peer.send_async(cx, &self.request(1, "server/discover", json!({})))
                    .await
                    .unwrap();
                let result = response(cx, peer, 1).await;
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
                            "clientInfo": {"name": "native-facade-peer", "version": "1.0"},
                        }),
                    ),
                )
                .await
                .unwrap();
                let result = response(cx, peer, 1).await;
                assert_eq!(
                    result["protocolVersion"],
                    fastmcp_rust::legacy_2024::PROTOCOL_VERSION
                );
                assert_eq!(
                    result["serverInfo"],
                    json!({"name": "facade-native-stdio", "version": "1.2.3"})
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
}

async fn response(cx: &Cx, peer: &mut Peer, id: i64) -> JsonValue {
    let JsonRpcMessage::Response(response) = peer.recv_async(cx).await.unwrap() else {
        panic!("expected the response to request {id}");
    };
    assert_eq!(response.id, Some(RequestId::Number(id)));
    assert!(response.error.is_none(), "{:?}", response.error);
    response.result.expect("successful response has a result")
}

fn run_facade(facade: Facade, era: PeerEra) {
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
            let (server_input, peer_output) = create_native_pipe(&cx).unwrap();
            let (peer_input, server_output) = create_native_pipe(&cx).unwrap();
            let mut peer = AsyncStdioTransport::from_io(peer_input, peer_output);
            let stopped = Arc::new(AtomicBool::new(false));
            let server_stopped = Arc::clone(&stopped);
            let mut serving = cx
                .spawn(move |serve_cx| async move {
                    facade
                        .serve(&serve_cx, server_input, server_output, server_stopped)
                        .await
                })
                .unwrap();

            era.open(&cx, &mut peer).await;
            let expected = format!("{facade:?} {era:?} echo");
            peer.send_async(
                &cx,
                &era.request(
                    2,
                    "tools/call",
                    json!({"name": "facade_echo", "arguments": {"value": expected}}),
                ),
            )
            .await
            .unwrap();
            let result = response(&cx, &mut peer, 2).await;
            assert_eq!(
                result["content"],
                json!([{"type": "text", "text": expected}])
            );
            assert_ne!(result["isError"], true);
            match era {
                PeerEra::Modern => assert_eq!(result["resultType"], "complete"),
                #[cfg(feature = "legacy-2024-11-05")]
                PeerEra::Legacy => assert!(result.get("resultType").is_none()),
            }

            assert!(!stopped.load(Ordering::Acquire));
            peer.close_async(&cx).await.unwrap();
            serving.join(&cx).await.unwrap().unwrap();
            assert!(stopped.load(Ordering::Acquire));
            assert!(cx.checkpoint().is_ok());
        })
        .await
        .expect("native facade serving must make bounded caller-runtime progress");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn modern_facade_native_stdio_runs_on_caller_runtime() {
    run_facade(Facade::Modern, PeerEra::Modern);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn auto_facade_native_stdio_selects_modern() {
    run_facade(Facade::Auto, PeerEra::Modern);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn auto_facade_native_stdio_selects_exact_legacy() {
    run_facade(Facade::Auto, PeerEra::Legacy);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn legacy_facade_native_stdio_serves_exact_legacy() {
    run_facade(Facade::Legacy, PeerEra::Legacy);
}
