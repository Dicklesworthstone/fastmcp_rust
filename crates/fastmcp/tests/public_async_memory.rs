//! Public in-process serving on a caller-owned runtime without a reactor or
//! blocking pool. The modern facade also runs with `--no-default-features`.

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
