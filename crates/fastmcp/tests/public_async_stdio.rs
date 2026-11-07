//! Real native-pipe round trips through the public, era-pinned facade APIs.
//!
//! The modern case also runs with `--no-default-features`. All handlers and
//! transport endpoints use one caller-owned runtime with no blocking pool.

#![cfg(unix)]
// An integration test is its own crate root, so it inherits no attribute from
// the facade's `src/lib.rs` -- which does not raise this either. Proving `Send`
// for the nested `Facade::serve` -> `serve_stdio_io` async blocks spawned below
// overflows the default limit, and rustc then ABANDONS the proof rather than
// failing it, leaving those futures unchecked rather than shown `Send`. The two
// sibling crates with async graphs this deep raise it for the same reason; see
// bd-35ktc.
#![recursion_limit = "512"]
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

fn run_subscription_shutdown(cancel_first: bool) {
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
            let (server_input, peer_output) = create_native_pipe(&cx).unwrap();
            let (peer_input, server_output) = create_native_pipe(&cx).unwrap();
            let mut peer = AsyncStdioTransport::from_io(peer_input, peer_output);
            let stopped = Arc::new(AtomicBool::new(false));
            let server_stopped = Arc::clone(&stopped);
            let (server_cx_tx, server_cx_rx) = std::sync::mpsc::sync_channel(1);
            let mut serving = cx
                .spawn(move |serve_cx| async move {
                    server_cx_tx.send(serve_cx.clone()).unwrap();
                    Facade::Modern
                        .serve(&serve_cx, server_input, server_output, server_stopped)
                        .await
                })
                .unwrap();
            PeerEra::Modern.open(&cx, &mut peer).await;
            for id in [41, 42] {
                peer.send_async(
                    &cx,
                    &PeerEra::Modern.request(
                        id,
                        "subscriptions/listen",
                        json!({"notifications": {}}),
                    ),
                )
                .await
                .unwrap();
                let JsonRpcMessage::Request(acknowledgement) =
                    peer.recv_async(&cx).await.unwrap()
                else {
                    panic!("an empty-filter listen must receive acknowledgement first");
                };
                assert!(acknowledgement.id.is_none());
                assert_eq!(
                    acknowledgement.method,
                    "notifications/subscriptions/acknowledged"
                );
                let params = acknowledgement.params.unwrap();
                assert_eq!(params["notifications"], json!({}));
                assert_eq!(params["_meta"]["io.modelcontextprotocol/subscriptionId"], id);
            }

            if cancel_first {
                // Client cancellation identifies its request without inventing
                // the server-only subscription metadata marker.
                peer.send_async(
                    &cx,
                    &JsonRpcMessage::Request(JsonRpcRequest::notification(
                        "notifications/cancelled",
                        Some(json!({"requestId": 41})),
                    )),
                )
                .await
                .unwrap();
            }
            peer.send_async(
                &cx,
                &PeerEra::Modern.request(
                    99,
                    "tools/call",
                    json!({"name": "facade_echo", "arguments": {"value": "still live"}}),
                ),
            )
            .await
            .unwrap();
            let result = response(&cx, &mut peer, 99).await;
            assert_eq!(result["content"], json!([{"type": "text", "text": "still live"}]));
            assert!(!stopped.load(Ordering::Acquire));

            server_cx_rx.try_recv().unwrap().cancel_with(
                asupersync::types::CancelKind::User,
                Some("public native stdio subscription shutdown"),
            );
            let mut cancelled = Vec::new();
            loop {
                match peer.recv_async(&cx).await {
                    Ok(JsonRpcMessage::Request(control)) => {
                        assert!(control.id.is_none());
                        assert_eq!(control.method, "notifications/cancelled");
                        let params = control.params.unwrap();
                        assert_eq!(
                            params["requestId"],
                            params["_meta"]["io.modelcontextprotocol/subscriptionId"]
                        );
                        cancelled.push(params["requestId"].as_i64().unwrap());
                    }
                    Ok(JsonRpcMessage::Response(response)) => {
                        panic!("server teardown must not fabricate a complete result: {response:?}");
                    }
                    Err(error) if error.is_closed() => break,
                    Err(error) => panic!("native stdio teardown must close cleanly: {error}"),
                }
            }
            cancelled.sort_unstable();
            assert_eq!(cancelled, if cancel_first { vec![42] } else { vec![41, 42] });
            serving.join(&cx).await.unwrap().unwrap();
            assert!(stopped.load(Ordering::Acquire));
            assert!(cx.checkpoint().is_ok());
        })
        .await
        .expect("subscription teardown must finish on the caller's native-pipe runtime");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn modern_facade_native_stdio_shutdown_emits_only_subscription_cancellation() {
    run_subscription_shutdown(false);
}

#[test]
fn modern_facade_native_stdio_peer_cancel_preserves_sibling_without_a_response() {
    run_subscription_shutdown(true);
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

#[test]
fn modern_facade_stdio_live_progress_preserves_all_typed_results() {
    fn require_send<F: std::future::Future + Send>(future: F) -> F {
        future
    }

    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        let discovery = modern::ServerDiscoverResult::new(
            modern::ServerDiscoverCapabilities::from_registry(
                &modern::ServerBehaviorRegistry::default(),
                std::collections::BTreeMap::new(),
            )
            .unwrap(),
            serde_json::from_value(json!({
                "name": "public-live-progress-peer",
                "version": "1.0.0",
            }))
            .unwrap(),
            None,
            modern::DiscoveryCacheHints::private_ttl_ms(0),
        );
        let discovery = serde_json::to_string(&discovery).unwrap();
        let script = r#"
numeric_id() {
    printf '%s\n' "$1" | sed -n 's/.*"id":\([0-9][0-9]*\)[,}].*/\1/p'
}
IFS= read -r discover || exit 10
case "$discover" in *'"method":"server/discover"'*) ;; *) exit 11 ;; esac
id=$(numeric_id "$discover")
case "$id" in ''|*[!0-9]*) exit 12 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$id" "$1"
for method in tools/call resources/read prompts/get completion/complete; do
    IFS= read -r request || exit 13
    case "$request" in *'"method":"'"$method"'"'*) ;; *) exit 14 ;; esac
    id=$(numeric_id "$request")
    token=$(printf '%s\n' "$request" | sed -n 's/.*"progressToken":\([0-9][0-9]*\)[,}].*/\1/p')
    case "$id" in ''|*[!0-9]*) exit 15 ;; esac
    case "$token" in ''|*[!0-9]*) exit 16 ;; esac
    case "$method" in
        tools/call)
            case "$request" in *'"name":"echo"'*) ;; *) exit 17 ;; esac
            case "$request" in *'"value":"tool input"'*) ;; *) exit 18 ;; esac
            result='{"resultType":"complete","content":[{"type":"text","text":"tool result"}]}'
            ;;
        resources/read)
            case "$request" in *'"uri":"test://resource"'*) ;; *) exit 19 ;; esac
            result='{"resultType":"complete","contents":[{"uri":"test://resource","text":"resource result"}],"ttlMs":0,"cacheScope":"private"}'
            ;;
        prompts/get)
            case "$request" in *'"name":"greet"'*) ;; *) exit 20 ;; esac
            case "$request" in *'"person":"Ada"'*) ;; *) exit 21 ;; esac
            result='{"resultType":"complete","description":"greeting","messages":[{"role":"user","content":{"type":"text","text":"Hello Ada"}}]}'
            ;;
        completion/complete)
            case "$request" in *'"type":"ref/prompt"'*) ;; *) exit 22 ;; esac
            case "$request" in *'"name":"person"'*) ;; *) exit 23 ;; esac
            case "$request" in *'"value":"A"'*) ;; *) exit 24 ;; esac
            case "$request" in *'"context":{"arguments":{"style":"formal"}}'*) ;; *) exit 25 ;; esac
            result='{"resultType":"complete","completion":{"values":["Ada","Alan"],"total":2,"hasMore":false}}'
            ;;
    esac
    printf '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":%s,"progress":1.2300e+400,"total":9.8700e+500,"message":"%s"}}\n' "$token" "$method"
    printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$id" "$result"
done
while IFS= read -r unexpected; do exit 26; done
"#;
        let mut client = modern::ClientBuilder::new()
            .request_timeout_policy(
                modern::RequestTimeoutPolicy::new(
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .unwrap(),
            )
            .connect_stdio_with_cx(
                &cx,
                "sh",
                &["-c", script, "public-progress-peer", &discovery],
            )
            .await
            .unwrap();
        let cancellation = modern::McpRequestCancellation::new();
        let mut progress = Vec::new();

        let tool = require_send(client.call_tool_result_with_progress(
            &cx,
            &cancellation,
            "echo",
            json!({"value": "tool input"}),
            |update| progress.push(update.clone()),
        ))
        .await
        .unwrap();
        let modern::FinalCoreResult::ToolsCall { result, .. } = tool else {
            panic!("the public tool method must retain its typed final result");
        };
        assert_eq!(result.payload.content, vec![modern::ContentBlock::text("tool result")]);

        let resource = require_send(client.read_resource_result_with_progress(
            &cx,
            &cancellation,
            "test://resource",
            |update| progress.push(update.clone()),
        ))
        .await
        .unwrap();
        let modern::FinalCoreResult::ResourcesRead { result, .. } = resource else {
            panic!("the public resource method must retain its typed final result");
        };
        assert_eq!(
            serde_json::to_value(result.payload.contents).unwrap(),
            json!([{"uri": "test://resource", "text": "resource result"}])
        );

        let prompt = require_send(client.get_prompt_result_with_progress(
            &cx,
            &cancellation,
            "greet",
            std::collections::HashMap::from([("person".to_owned(), "Ada".to_owned())]),
            |update| progress.push(update.clone()),
        ))
        .await
        .unwrap();
        let modern::FinalCoreResult::PromptsGet { result, .. } = prompt else {
            panic!("the public prompt method must retain its typed final result");
        };
        assert_eq!(
            serde_json::to_value(result.payload).unwrap(),
            json!({
                "description": "greeting",
                "messages": [{"role": "user", "content": {"type": "text", "text": "Hello Ada"}}],
            })
        );

        let completion = require_send(client.complete_with_progress(
            &cx,
            &cancellation,
            serde_json::from_value::<modern::CompletionParams>(json!({
                "ref": {"type": "ref/prompt", "name": "greet"},
                "argument": {"name": "person", "value": "A"},
                "context": {"arguments": {"style": "formal"}},
            }))
            .unwrap(),
            |update| progress.push(update.clone()),
        ))
        .await
        .unwrap();
        assert_eq!(
            serde_json::to_value(completion).unwrap(),
            json!({"completion": {"values": ["Ada", "Alan"], "total": 2, "hasMore": false}})
        );

        assert_eq!(progress.len(), 4);
        let mut tokens = std::collections::BTreeSet::new();
        for (update, method) in progress.iter().zip([
            "tools/call",
            "resources/read",
            "prompts/get",
            "completion/complete",
        ]) {
            assert_eq!(update.progress.as_str(), "1.2300e+400");
            assert_eq!(update.total.as_ref().unwrap().as_str(), "9.8700e+500");
            assert_eq!(update.message.as_deref(), Some(method));
            assert!(tokens.insert(serde_json::to_string(&update.progress_token).unwrap()));
        }
        assert!(client.take_progress_notifications().is_empty());
        assert!(cx.checkpoint().is_ok());
        client.close_with_cx(&cx).await.unwrap();
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}
