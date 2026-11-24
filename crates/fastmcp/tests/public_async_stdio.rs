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
        let bound = match self {
            Self::Modern => modern::ServerBuilder::new("facade-native-stdio", "1.2.3")
                .tool(FacadeEcho)
                .on_shutdown(shutdown)
                .build()
                .bind_stdio_io(reader, writer),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Auto => fastmcp_rust::auto::ServerBuilder::new("facade-native-stdio", "1.2.3")
                .tool(FacadeEcho)
                .on_shutdown(shutdown)
                .build()
                .bind_stdio_io(reader, writer),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Legacy => {
                fastmcp_rust::legacy_2024::ServerBuilder::new("facade-native-stdio", "1.2.3")
                    .tool(FacadeEcho)
                    .on_shutdown(shutdown)
                    .build()
                    .bind_stdio_io(reader, writer)
            }
        };
        let operator: fastmcp_rust::StdioOperatorHandle = bound.operator_handle();
        let starting: fastmcp_rust::OperatorStdioSnapshot =
            fastmcp_rust::OperatorSnapshot::capture(&operator).unwrap();
        assert_eq!(
            starting.readiness(),
            fastmcp_rust::OperatorReadiness::Starting
        );
        let profile = match self {
            Self::Modern => fastmcp_rust::OperatorProfile::Modern,
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Auto => fastmcp_rust::OperatorProfile::Auto,
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Legacy => fastmcp_rust::OperatorProfile::Legacy2024,
        };
        assert_eq!(starting.profile(), profile);
        let result = bound.serve(cx).await;
        let stopped = fastmcp_rust::OperatorSnapshot::capture(&operator).unwrap();
        assert_eq!(
            stopped.lifecycle(),
            fastmcp_rust::OperatorLifecycle::Stopped
        );
        assert_eq!(stopped.contributor().capacity.retained_frames, 0);
        assert_eq!(stopped.contributor().capacity.retained_bytes, 0);
        assert_eq!(
            stopped.contributor().counters.enqueued,
            stopped.contributor().counters.released,
        );
        assert_eq!(
            stopped.configuration_generation(),
            starting.configuration_generation(),
        );
        result
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
                let JsonRpcMessage::Request(acknowledgement) = peer.recv_async(&cx).await.unwrap()
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
                assert_eq!(
                    params["_meta"]["io.modelcontextprotocol/subscriptionId"],
                    id
                );
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
            assert_eq!(
                result["content"],
                json!([{"type": "text", "text": "still live"}])
            );
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
                        panic!(
                            "server teardown must not fabricate a complete result: {response:?}"
                        );
                    }
                    Err(error) if error.is_closed() => break,
                    Err(error) => panic!("native stdio teardown must close cleanly: {error}"),
                }
            }
            cancelled.sort_unstable();
            assert_eq!(
                cancelled,
                if cancel_first { vec![42] } else { vec![41, 42] }
            );
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

mod async_modern_client {
    use super::*;
    use std::collections::HashMap;
    use std::future::Future;
    use std::sync::atomic::AtomicUsize;
    use std::task::Poll;

    const DISCOVER: &str = r#"
numeric_id() {
    printf '%s\n' "$1" | sed -n 's/.*"id":\([0-9][0-9]*\)[,}].*/\1/p'
}
read_request() {
    IFS= read -r request || exit 10
    id=$(numeric_id "$request")
    case "$id" in ''|*[!0-9]*) exit 11 ;; esac
}
read_request
case "$request" in *'"method":"server/discover"'*) ;; *) exit 12 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$id" "$1"
"#;

    fn require_send<F: Future + Send>(future: F) -> F {
        future
    }

    fn run<F, Fut>(test: F)
    where
        F: FnOnce(Cx) -> Fut,
        Fut: Future<Output = ()>,
    {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(cx.blocking_pool_handle().is_none());
            asupersync::time::timeout(cx.now(), Duration::from_secs(20), test(cx))
                .await
                .expect("the public workflow must finish on the caller's runtime");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    fn discovery() -> String {
        discovery_with_extensions(std::collections::BTreeMap::new())
    }

    fn discovery_with_extensions(
        extensions: std::collections::BTreeMap<String, JsonValue>,
    ) -> String {
        serde_json::to_string(&modern::ServerDiscoverResult::new(
            modern::ServerDiscoverCapabilities::from_registry(
                &modern::ServerBehaviorRegistry::default(),
                extensions,
            )
            .unwrap(),
            serde_json::from_value(json!({
                "name": "public-async-client-peer",
                "version": "1.0.0",
            }))
            .unwrap(),
            None,
            modern::DiscoveryCacheHints::private_ttl_ms(0),
        ))
        .unwrap()
    }

    async fn connect(cx: &Cx, script: &str, builder: modern::ClientBuilder) -> modern::Client {
        builder
            .max_retries(0)
            .request_timeout_policy(
                modern::RequestTimeoutPolicy::new(Duration::from_secs(5), Duration::from_secs(5))
                    .unwrap(),
            )
            .connect_stdio_with_cx(cx, "sh", &["-c", script, "public-async-peer", &discovery()])
            .await
            .unwrap()
    }

    /// The response cannot arrive until the caller has observed a Pending poll.
    /// The peer's finite loop also turns a synchronous-wait regression into a
    /// bounded failure instead of hanging this single-worker test indefinitely.
    struct DiscoveryRelease {
        path: std::path::PathBuf,
    }

    impl DiscoveryRelease {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "fastmcp-facade-discovery-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::File::create_new(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &str {
            self.path.to_str().unwrap()
        }

        fn release(&self) {
            std::fs::write(&self.path, b"ready\n").unwrap();
        }
    }

    impl Drop for DiscoveryRelease {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    const DEFERRED_METADATA_PEER: &str = r#"
IFS= read -r request || exit 90
case "$3" in
    modern)
        case "$request" in *'"method":"server/discover"'*) ;; *) exit 91 ;; esac
        ;;
    legacy)
        case "$request" in *'"method":"initialize"'*) ;; *) exit 92 ;; esac
        case "$request" in *'"protocolVersion":"2024-11-05"'*) ;; *) exit 92 ;; esac
        ;;
    *) exit 93 ;;
esac
id=$(printf '%s\n' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\)[,}].*/\1/p')
[ "$id" = 1 ] || exit 94
turn=0
while [ ! -s "$2" ]; do
    turn=$((turn + 1))
    [ "$turn" -le 3000 ] || exit 95
    sleep 0.001
done
printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$id" "$1"
if [ "$3" = legacy ]; then
    IFS= read -r initialized || exit 96
    case "$initialized" in *'"method":"notifications/initialized"'*) ;; *) exit 97 ;; esac
    printf 'initialized\n' > "$2"
fi
while IFS= read -r unexpected; do exit 98; done
"#;

    async fn deferred_metadata_client(
        cx: &Cx,
        release: &DiscoveryRelease,
        discovery: &JsonValue,
    ) -> modern::Client {
        modern::ClientBuilder::new()
            .auto_initialize(true)
            .max_retries(0)
            .request_timeout_policy(
                modern::RequestTimeoutPolicy::new(Duration::from_secs(5), Duration::from_secs(5))
                    .unwrap(),
            )
            .connect_stdio_with_cx(
                cx,
                "sh",
                &[
                    "-c",
                    DEFERRED_METADATA_PEER,
                    "public-deferred-metadata-peer",
                    &discovery.to_string(),
                    release.path(),
                    "modern",
                ],
            )
            .await
            .unwrap()
    }

    fn discovery_with_instructions() -> JsonValue {
        let mut result: JsonValue = serde_json::from_str(&discovery()).unwrap();
        result["instructions"] = json!("Use only the admitted peer's instructions.");
        result
    }

    #[test]
    fn modern_deferred_metadata_yields_and_resumes_the_same_handshake() {
        run(|cx| async move {
            let release = DiscoveryRelease::new();
            let expected = discovery_with_instructions();
            let mut client = deferred_metadata_client(&cx, &release, &expected).await;
            let mut discovering = Box::pin(require_send(client.server_discovery_with_cx(&cx)));
            let yielded = std::future::poll_fn(|task_cx| {
                Poll::Ready(discovering.as_mut().poll(task_cx).is_pending())
            })
            .await;
            assert!(
                yielded,
                "deferred discovery must yield before the peer replies"
            );
            drop(discovering);

            // A dropped metadata read preserves the one published discovery
            // request. The peer accepts ID 1 once and never answers a duplicate.
            release.release();
            assert_eq!(
                require_send(client.instructions_with_cx(&cx))
                    .await
                    .unwrap(),
                expected["instructions"].as_str(),
            );
            require_send(client.ensure_initialized_with_cx(&cx))
                .await
                .unwrap();
            assert_eq!(
                serde_json::to_value(
                    require_send(client.server_discovery_with_cx(&cx))
                        .await
                        .unwrap(),
                )
                .unwrap(),
                expected,
            );
            assert_eq!(client.protocol_version(), modern::PROTOCOL_VERSION);
            assert!(cx.checkpoint().is_ok());
            client.close_with_cx(&cx).await.unwrap();
        });
    }

    #[test]
    fn modern_deferred_metadata_cancellation_before_publication_preserves_connection() {
        run(|cx| async move {
            let release = DiscoveryRelease::new();
            let expected = discovery_with_instructions();
            let mut client = deferred_metadata_client(&cx, &release, &expected).await;

            // A separate cancelled caller cannot borrow the healthy ambient
            // runtime's authority or consume the connection's first request ID.
            let cancelled = Cx::for_request();
            cancelled.set_cancel_requested(true);
            let error = require_send(client.ensure_initialized_with_cx(&cancelled))
                .await
                .unwrap_err();
            assert_eq!(error.code, fastmcp_rust::McpErrorCode::RequestCancelled);
            let error = require_send(client.server_discovery_with_cx(&cancelled))
                .await
                .unwrap_err();
            assert_eq!(error.code, fastmcp_rust::McpErrorCode::RequestCancelled);
            let error = require_send(client.instructions_with_cx(&cancelled))
                .await
                .unwrap_err();
            assert_eq!(error.code, fastmcp_rust::McpErrorCode::RequestCancelled);

            release.release();
            assert_eq!(
                require_send(client.instructions_with_cx(&cx))
                    .await
                    .unwrap(),
                expected["instructions"].as_str(),
            );
            assert!(cx.checkpoint().is_ok());
            client.close_with_cx(&cx).await.unwrap();
        });
    }

    #[test]
    fn modern_deferred_metadata_never_exposes_an_unsupported_peers_instructions() {
        run(|cx| async move {
            let release = DiscoveryRelease::new();
            let mut unsupported = discovery_with_instructions();
            unsupported["supportedVersions"] = json!(["1999-01-01"]);
            let mut client = deferred_metadata_client(&cx, &release, &unsupported).await;
            release.release();

            let rejected = require_send(client.instructions_with_cx(&cx))
                .await
                .expect_err("an incompatible peer cannot supply admitted instructions");
            let retained = require_send(client.server_discovery_with_cx(&cx))
                .await
                .expect_err("metadata access cannot restart a rejected handshake");
            assert_eq!(retained.code, rejected.code);
            assert_eq!(retained.message, rejected.message);
            assert!(cx.checkpoint().is_ok());
            client.close_with_cx(&cx).await.unwrap();
        });
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn legacy_deferred_metadata_and_close_stay_on_the_caller_runtime() {
        run(|cx| async move {
            let release = DiscoveryRelease::new();
            let response = json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "deferred-legacy-peer", "version": "1.0"},
                "instructions": "Exact legacy instructions.",
            });
            let mut client = fastmcp_rust::legacy_2024::ClientBuilder::new()
                .auto_initialize(true)
                .max_retries(0)
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
                    &[
                        "-c",
                        DEFERRED_METADATA_PEER,
                        "public-deferred-legacy-peer",
                        &response.to_string(),
                        release.path(),
                        "legacy",
                    ],
                )
                .await
                .unwrap();
            assert!(!client.is_initialized());
            let mut initializing = Box::pin(require_send(client.ensure_initialized_with_cx(&cx)));
            let yielded = std::future::poll_fn(|task_cx| {
                Poll::Ready(initializing.as_mut().poll(task_cx).is_pending())
            })
            .await;
            assert!(yielded, "deferred legacy initialization must yield");
            drop(initializing);
            release.release();

            assert_eq!(
                require_send(client.instructions_with_cx(&cx))
                    .await
                    .unwrap(),
                Some("Exact legacy instructions."),
            );
            assert!(client.is_initialized());
            assert_eq!(client.protocol_version(), "2024-11-05");
            assert_eq!(client.server_info().name, "deferred-legacy-peer");
            require_send(client.ensure_initialized_with_cx(&cx))
                .await
                .unwrap();
            // Observe the peer accepting the exact lifecycle notification;
            // a child exit code during close is not that acknowledgement.
            while std::fs::read(&release.path).unwrap() != b"initialized\n" {
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
            require_send(client.close_with_cx(&cx)).await.unwrap();
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[cfg(feature = "legacy-2024-11-05")]
    mod legacy_operations {
        use super::{DiscoveryRelease, require_send, run};
        use fastmcp_rust::{Cx, JsonValue, McpErrorCode, McpResult, json, legacy_2024 as legacy};
        use std::collections::HashMap;
        use std::future::Future;
        use std::task::Poll;
        use std::time::Duration;

        const INITIALIZE: &str = r#"
next_id=1
read_request() {
    IFS= read -r request || exit 70
    id=$(printf '%s\n' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\)[,}].*/\1/p')
    [ "$id" = "$next_id" ] || exit 71
    next_id=$((next_id + 1))
    case "$request" in *'io.modelcontextprotocol/'*|*'"resultType":'*) exit 72 ;; esac
}
read_request
case "$request" in *'"method":"initialize"'*) ;; *) exit 73 ;; esac
case "$request" in *'"protocolVersion":"2024-11-05"'*) ;; *) exit 74 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{},"resources":{"subscribe":true},"prompts":{},"logging":{}},"serverInfo":{"name":"async-legacy-peer","version":"1.0"}}}\n' "$id"
IFS= read -r initialized || exit 75
case "$initialized" in *'"method":"notifications/initialized"'*) ;; *) exit 76 ;; esac
"#;

        async fn connect(cx: &Cx, script: &str, release: &str) -> legacy::Client {
            legacy::ClientBuilder::new()
                .auto_initialize(false)
                .max_retries(0)
                .request_timeout_policy(
                    legacy::RequestTimeoutPolicy::new(
                        Duration::from_secs(5),
                        Duration::from_secs(5),
                    )
                    .unwrap(),
                )
                .connect_stdio_with_cx(
                    cx,
                    "sh",
                    &["-c", script, "public-async-legacy-operations", release],
                )
                .await
                .unwrap()
        }

        async fn page(
            client: &mut legacy::Client,
            cx: &Cx,
            cancellation: &legacy::McpRequestCancellation,
            method: &str,
            params: JsonValue,
        ) -> McpResult<JsonValue> {
            let result = match method {
                "tools/list" => serde_json::to_value(
                    client
                        .list_tools_with_cx(
                            cx,
                            cancellation,
                            serde_json::from_value(params).unwrap(),
                        )
                        .await?,
                ),
                "resources/list" => serde_json::to_value(
                    client
                        .list_resources_with_cx(
                            cx,
                            cancellation,
                            serde_json::from_value(params).unwrap(),
                        )
                        .await?,
                ),
                "resources/templates/list" => serde_json::to_value(
                    client
                        .list_resource_templates_with_cx(
                            cx,
                            cancellation,
                            serde_json::from_value(params).unwrap(),
                        )
                        .await?,
                ),
                "prompts/list" => serde_json::to_value(
                    client
                        .list_prompts_with_cx(
                            cx,
                            cancellation,
                            serde_json::from_value(params).unwrap(),
                        )
                        .await?,
                ),
                _ => unreachable!(),
            };
            Ok(result.unwrap())
        }

        async fn collect(
            client: &mut legacy::Client,
            cx: &Cx,
            cancellation: &legacy::McpRequestCancellation,
            method: &str,
            params: JsonValue,
        ) -> McpResult<legacy::CollectedCatalog> {
            match method {
                "tools/list" => {
                    client
                        .list_all_tools_with_cx(
                            cx,
                            cancellation,
                            serde_json::from_value(params).unwrap(),
                        )
                        .await
                }
                "resources/list" => {
                    client
                        .list_all_resources_with_cx(
                            cx,
                            cancellation,
                            serde_json::from_value(params).unwrap(),
                        )
                        .await
                }
                "resources/templates/list" => {
                    client
                        .list_all_resource_templates_with_cx(
                            cx,
                            cancellation,
                            serde_json::from_value(params).unwrap(),
                        )
                        .await
                }
                "prompts/list" => {
                    client
                        .list_all_prompts_with_cx(
                            cx,
                            cancellation,
                            serde_json::from_value(params).unwrap(),
                        )
                        .await
                }
                _ => unreachable!(),
            }
        }

        fn page_value(page: &legacy::LegacyCoreResult) -> JsonValue {
            match page {
                legacy::LegacyCoreResult::ToolsList(result) => serde_json::to_value(result),
                legacy::LegacyCoreResult::ResourcesList(result) => serde_json::to_value(result),
                legacy::LegacyCoreResult::ResourceTemplatesList(result) => {
                    serde_json::to_value(result)
                }
                legacy::LegacyCoreResult::PromptsList(result) => serde_json::to_value(result),
                _ => panic!("catalogs must retain only their own legacy result family"),
            }
            .unwrap()
        }

        #[test]
        fn legacy_async_catalog_pages_and_collections_preserve_typed_cursors() {
            run(|cx| async move {
                const CURSOR: &str = " opaque /+=? token ";
                let catalogs = [
                    (
                        "tools/list",
                        "tools",
                        json!({"name": "echo", "inputSchema": {"type": "object"}}),
                    ),
                    (
                        "resources/list",
                        "resources",
                        json!({"name": "source", "uri": "test://source"}),
                    ),
                    (
                        "resources/templates/list",
                        "resourceTemplates",
                        json!({"name": "source", "uriTemplate": "test://source/{name}"}),
                    ),
                    ("prompts/list", "prompts", json!({"name": "greet"})),
                ];
                let mut script = INITIALIZE.to_owned();
                for (method, field, item) in &catalogs {
                    // One caller-controlled page followed by one complete traversal.
                    for index in 0..5 {
                        script.push_str(&format!(
                            "read_request\n\
                             case \"$request\" in *'\"method\":\"{method}\"'*) ;; *) exit 80 ;; esac\n\
                             case \"$request\" in *'\"includeTags\":[\"visible\"]'*) ;; *) exit 81 ;; esac\n\
                             case \"$request\" in *'\"excludeTags\":[\"hidden\"]'*) ;; *) exit 82 ;; esac\n"
                        ));
                        script.push_str(match index {
                            0 => "case \"$request\" in *'\"cursor\":\"one page\"'*) ;; *) exit 83 ;; esac\n",
                            1 => "case \"$request\" in *'\"cursor\":'*) exit 84 ;; esac\n",
                            2 => "case \"$request\" in *'\"cursor\":\"\"'*) ;; *) exit 85 ;; esac\n",
                            _ => "case \"$request\" in *'\"cursor\":\" opaque /+=? token \"'*) ;; *) exit 86 ;; esac\n",
                        });
                        let mut result = json!({});
                        result[*field] = if index == 2 { json!([]) } else { json!([item]) };
                        if index < 4 {
                            result["nextCursor"] = json!(if index == 1 { "" } else { CURSOR });
                        }
                        script.push_str(&format!(
                            "printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{result}}}\\n' \"$id\"\n"
                        ));
                    }
                }
                script.push_str("while IFS= read -r unexpected; do exit 87; done\n");
                let mut client = connect(&cx, &script, "").await;
                let cancellation = legacy::McpRequestCancellation::new();
                let cancelled = legacy::McpRequestCancellation::new();
                cancelled.cancel();
                for (method, field, item) in catalogs {
                    let params = json!({"includeTags": ["visible"], "excludeTags": ["hidden"]});
                    let mut single_params = params.clone();
                    single_params["cursor"] = json!("one page");
                    let error = require_send(page(
                        &mut client,
                        &cx,
                        &cancelled,
                        method,
                        single_params.clone(),
                    ))
                    .await
                    .unwrap_err();
                    assert_eq!(error.code, McpErrorCode::RequestCancelled);
                    let first =
                        require_send(page(&mut client, &cx, &cancellation, method, single_params))
                            .await
                            .unwrap();
                    assert_eq!(first[field], json!([item]));
                    assert_eq!(first["nextCursor"], json!(CURSOR));

                    let mut invalid_start = params.clone();
                    invalid_start["cursor"] = json!("");
                    let error = require_send(collect(
                        &mut client,
                        &cx,
                        &cancellation,
                        method,
                        invalid_start,
                    ))
                    .await
                    .unwrap_err();
                    assert_eq!(error.code, McpErrorCode::InvalidParams);
                    let error = require_send(collect(
                        &mut client,
                        &cx,
                        &cancelled,
                        method,
                        params.clone(),
                    ))
                    .await
                    .unwrap_err();
                    assert_eq!(error.code, McpErrorCode::RequestCancelled);
                    let catalog =
                        require_send(collect(&mut client, &cx, &cancellation, method, params))
                            .await
                            .unwrap();
                    assert_eq!(catalog.method(), method);
                    assert_eq!(catalog.item_count(), 3);
                    let pages: &[legacy::LegacyCoreResult] = catalog.pages();
                    assert_eq!(pages.len(), 4);
                    for (index, page) in pages.iter().enumerate() {
                        assert_eq!(page.method(), method);
                        let value = page_value(page);
                        assert_eq!(
                            value[field].as_array().unwrap().len(),
                            usize::from(index != 1)
                        );
                        assert!(value.get("resultType").is_none());
                        let expected = match index {
                            0 => Some(json!("")),
                            1 | 2 => Some(json!(CURSOR)),
                            _ => None,
                        };
                        assert_eq!(value.get("nextCursor"), expected.as_ref());
                    }
                    let owned: Vec<legacy::LegacyCoreResult> = catalog.into_pages();
                    assert_eq!(owned.len(), 4);
                }
                require_send(client.close_with_cx(&cx)).await.unwrap();
                assert!(cx.checkpoint().is_ok());
            });
        }

        #[test]
        fn legacy_async_content_and_controls_yield_and_preserve_wire() {
            run(|cx| async move {
                let release = DiscoveryRelease::new();
                let script = [INITIALIZE, r#"
read_request
case "$request" in *'"method":"ping"'*) ;; *) exit 80 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id"
read_request
case "$request" in *'"method":"logging/setLevel"'*) ;; *) exit 81 ;; esac
case "$request" in *'"level":"info"'*) ;; *) exit 82 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id"
read_request
case "$request" in *'"method":"resources/subscribe"'*) ;; *) exit 83 ;; esac
case "$request" in *'"uri":"test://async/value"'*) ;; *) exit 84 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id"
read_request
case "$request" in *'"method":"resources/read"'*) ;; *) exit 85 ;; esac
case "$request" in *'"uri":"test://async/value"'*) ;; *) exit 86 ;; esac
turn=0
while [ ! -s "$1" ]; do
    turn=$((turn + 1))
    [ "$turn" -le 3000 ] || exit 87
    sleep 0.001
done
printf '{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"test://async/value"}}\n'
printf '{"jsonrpc":"2.0","id":%s,"result":{"contents":[{"uri":"test://async/value","text":"resource value","mimeType":"text/plain","vendor":7}],"_meta":{"source":"legacy"},"vendorResult":"resource"}}\n' "$id"
read_request
case "$request" in *'"method":"prompts/get"'*) ;; *) exit 88 ;; esac
case "$request" in *'"arguments":{"name":"Ada"}'*) ;; *) exit 89 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"description":"legacy prompt","messages":[{"role":"user","content":{"type":"text","text":"Hello Ada","vendor":8}}],"_meta":{"source":"legacy"},"vendorResult":"prompt"}}\n' "$id"
read_request
case "$request" in *'"method":"completion/complete"'*) ;; *) exit 90 ;; esac
case "$request" in *'"progressToken":"legacy-complete"'*) ;; *) exit 91 ;; esac
case "$request" in *'"context":'*) exit 92 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"completion":{"values":["Ada"],"total":1,"hasMore":false},"_meta":{"source":"legacy","order":2}}}\n' "$id"
read_request
case "$request" in *'"method":"tools/call"'*) ;; *) exit 93 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"tool value","vendor":9}],"_meta":{"source":"legacy"},"vendorResult":"tool"}}\n' "$id"
read_request
case "$request" in *'"method":"resources/unsubscribe"'*) ;; *) exit 94 ;; esac
case "$request" in *'"uri":"test://async/value"'*) ;; *) exit 95 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id"
while IFS= read -r unexpected; do exit 96; done
"#].concat();
                let mut client = connect(&cx, &script, release.path()).await;
                let cancellation = legacy::McpRequestCancellation::new();
                let cancelled = legacy::McpRequestCancellation::new();
                cancelled.cancel();
                let cancelled_cx = Cx::for_request();
                cancelled_cx.set_cancel_requested(true);
                assert_eq!(
                    require_send(client.ping_with_cx(&cancelled_cx))
                        .await
                        .unwrap_err()
                        .code,
                    McpErrorCode::RequestCancelled,
                );
                assert_eq!(
                    require_send(
                        client.set_log_level_with_cx(&cancelled_cx, legacy::LogLevel::Info)
                    )
                    .await
                    .unwrap_err()
                    .code,
                    McpErrorCode::RequestCancelled,
                );
                assert_eq!(
                    require_send(
                        client.subscribe_resource_with_cx(&cancelled_cx, "test://async/value")
                    )
                    .await
                    .unwrap_err()
                    .code,
                    McpErrorCode::RequestCancelled,
                );
                assert_eq!(
                    require_send(
                        client.unsubscribe_resource_with_cx(&cancelled_cx, "test://async/value")
                    )
                    .await
                    .unwrap_err()
                    .code,
                    McpErrorCode::RequestCancelled,
                );
                assert_eq!(
                    require_send(client.read_resource_with_cx(
                        &cx,
                        &cancelled,
                        "test://async/value"
                    ))
                    .await
                    .unwrap_err()
                    .code,
                    McpErrorCode::RequestCancelled,
                );
                require_send(client.ping_with_cx(&cx)).await.unwrap();
                require_send(client.set_log_level_with_cx(&cx, legacy::LogLevel::Info))
                    .await
                    .unwrap();
                require_send(client.subscribe_resource_with_cx(&cx, "test://async/value"))
                    .await
                    .unwrap();

                let mut reading = Box::pin(require_send(client.read_resource_with_cx(
                    &cx,
                    &cancellation,
                    "test://async/value",
                )));
                let yielded = std::future::poll_fn(|task_cx| {
                    Poll::Ready(reading.as_mut().poll(task_cx).is_pending())
                })
                .await;
                assert!(yielded, "resource reads must yield before the peer replies");
                release.release();
                let resource = serde_json::to_value(reading.await.unwrap()).unwrap();
                assert_eq!(resource["contents"][0]["text"], "resource value");
                assert_eq!(resource["contents"][0]["vendor"], 7);
                assert_eq!(resource["_meta"]["source"], "legacy");
                assert_eq!(resource["vendorResult"], "resource");
                assert!(resource.get("resultType").is_none());

                let prompt = require_send(client.get_prompt_with_cx(
                    &cx,
                    &cancellation,
                    "greet",
                    HashMap::from([("name".to_owned(), "Ada".to_owned())]),
                ))
                .await
                .unwrap();
                let prompt = serde_json::to_value(prompt).unwrap();
                assert_eq!(prompt["messages"][0]["content"]["text"], "Hello Ada");
                assert_eq!(prompt["messages"][0]["content"]["vendor"], 8);
                assert_eq!(prompt["_meta"]["source"], "legacy");
                assert_eq!(prompt["vendorResult"], "prompt");

                let completed = require_send(
                    client.complete_with_cx(
                        &cx,
                        &cancellation,
                        serde_json::from_value(json!({
                            "ref": {"type": "ref/prompt", "name": "greet"},
                            "argument": {"name": "name", "value": "A"},
                            "_meta": {"progressToken": "legacy-complete"},
                        }))
                        .unwrap(),
                    ),
                )
                .await
                .unwrap();
                assert_eq!(completed.completion.values, ["Ada"]);
                assert_eq!(
                    completed.meta.as_ref().unwrap().get("source"),
                    Some(&json!("legacy"))
                );
                let tool =
                    require_send(client.call_tool_with_cx(&cx, "echo", json!({"value": "tool"})))
                        .await
                        .unwrap();
                let tool = serde_json::to_value(tool).unwrap();
                assert_eq!(tool["content"][0]["text"], "tool value");
                assert_eq!(tool["content"][0]["vendor"], 9);
                assert_eq!(tool["vendorResult"], "tool");
                require_send(client.unsubscribe_resource_with_cx(&cx, "test://async/value"))
                    .await
                    .unwrap();
                let notifications = client.take_server_notifications().unwrap();
                assert_eq!(notifications.len(), 1);
                assert!(matches!(
                    &notifications[0],
                    legacy::ServerNotification::ResourceUpdated(update)
                        if update.uri == "test://async/value"
                ));
                require_send(client.close_with_cx(&cx)).await.unwrap();
                assert!(cx.checkpoint().is_ok());
            });
        }

        #[test]
        fn legacy_async_catalog_error_returns_no_partial_collection_and_allows_reuse() {
            run(|cx| async move {
                let script = [INITIALIZE, r#"
read_request
case "$request" in *'"method":"tools/list"'*) ;; *) exit 80 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"partial","inputSchema":{"type":"object"}}],"nextCursor":"continuation"}}\n' "$id"
read_request
case "$request" in *'"cursor":"continuation"'*) ;; *) exit 81 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"continuation refused","data":{"page":2}}}\n' "$id"
read_request
case "$request" in *'"method":"ping"'*) ;; *) exit 82 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id"
read_request
case "$request" in *'"method":"prompts/list"'*) ;; *) exit 83 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"prompts":[{"name":"healthy"}]}}\n' "$id"
while IFS= read -r unexpected; do exit 84; done
"#].concat();
                let mut client = connect(&cx, &script, "").await;
                let cancellation = legacy::McpRequestCancellation::new();
                let error = require_send(client.list_all_tools_with_cx(
                    &cx,
                    &cancellation,
                    legacy::ListToolsParams::default(),
                ))
                .await
                .unwrap_err();
                assert_eq!(error.code, McpErrorCode::InternalError);
                assert_eq!(error.message, "continuation refused");
                assert_eq!(error.data, Some(json!({"page": 2})));
                require_send(client.ping_with_cx(&cx)).await.unwrap();
                let recovered = require_send(client.list_all_prompts_with_cx(
                    &cx,
                    &cancellation,
                    legacy::ListPromptsParams::default(),
                ))
                .await
                .unwrap();
                assert_eq!(recovered.item_count(), 1);
                assert_eq!(recovered.pages().len(), 1);
                assert_eq!(
                    page_value(&recovered.pages()[0])["prompts"][0]["name"],
                    "healthy"
                );
                require_send(client.close_with_cx(&cx)).await.unwrap();
            });
        }

        #[test]
        fn legacy_async_read_cancellation_retires_only_the_active_request() {
            run(|cx| async move {
                let script = [
                    INITIALIZE,
                    r#"
read_request
case "$request" in *'"method":"resources/read"'*) ;; *) exit 80 ;; esac
original_id=$id
IFS= read -r cancelled || exit 81
case "$cancelled" in *'"method":"notifications/cancelled"'*) ;; *) exit 82 ;; esac
case "$cancelled" in *'"requestId":2'*|*'"requestId":2}'*) ;; *) exit 83 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"contents":[]}}\n' "$original_id"
read_request
case "$request" in *'"method":"ping"'*) ;; *) exit 84 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{}}\n' "$id"
while IFS= read -r unexpected; do exit 85; done
"#,
                ]
                .concat();
                let mut client = connect(&cx, &script, "").await;
                require_send(client.ensure_initialized_with_cx(&cx))
                    .await
                    .unwrap();
                assert!(client.is_initialized());
                let cancellation = legacy::McpRequestCancellation::new();
                let mut reading = Box::pin(require_send(client.read_resource_with_cx(
                    &cx,
                    &cancellation,
                    "test://async/pending",
                )));
                let yielded = std::future::poll_fn(|task_cx| {
                    Poll::Ready(reading.as_mut().poll(task_cx).is_pending())
                })
                .await;
                assert!(yielded, "the peer holds the request until cancellation");
                cancellation.cancel();
                assert_eq!(
                    reading.await.unwrap_err().code,
                    McpErrorCode::RequestCancelled
                );
                require_send(client.ping_with_cx(&cx)).await.unwrap();
                assert!(cx.checkpoint().is_ok());
                require_send(client.close_with_cx(&cx)).await.unwrap();
            });
        }

        #[test]
        fn legacy_async_results_reject_one_field_modern_contamination() {
            run(|cx| async move {
                for (method, valid) in [
                    ("tools/list", json!({"tools": []})),
                    ("resources/read", json!({"contents": []})),
                    ("completion/complete", json!({"completion": {"values": []}})),
                    ("resources/subscribe", json!({})),
                    ("ping", json!({})),
                ] {
                    for contaminated in [false, true] {
                        let mut result = valid.clone();
                        if contaminated {
                            result["resultType"] = json!("complete");
                        }
                        let script = format!(
                            "{INITIALIZE}\n\
                             read_request\n\
                             case \"$request\" in *'\"method\":\"{method}\"'*) ;; *) exit 80 ;; esac\n\
                             printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{result}}}\\n' \"$id\"\n\
                             while IFS= read -r unexpected; do exit 81; done\n"
                        );
                        let mut client = connect(&cx, &script, "").await;
                        let cancellation = legacy::McpRequestCancellation::new();
                        let observed = match method {
                            "tools/list" => client
                                .list_tools_with_cx(
                                    &cx,
                                    &cancellation,
                                    legacy::ListToolsParams::default(),
                                )
                                .await
                                .map(|_| ()),
                            "resources/read" => client
                                .read_resource_with_cx(&cx, &cancellation, "test://source")
                                .await
                                .map(|_| ()),
                            "completion/complete" => client
                                .complete_with_cx(
                                    &cx,
                                    &cancellation,
                                    serde_json::from_value(json!({
                                        "ref": {"type": "ref/prompt", "name": "greet"},
                                        "argument": {"name": "name", "value": "A"},
                                    }))
                                    .unwrap(),
                                )
                                .await
                                .map(|_| ()),
                            "resources/subscribe" => {
                                client
                                    .subscribe_resource_with_cx(&cx, "test://source")
                                    .await
                            }
                            "ping" => client.ping_with_cx(&cx).await,
                            _ => unreachable!(),
                        };
                        if contaminated {
                            assert_eq!(observed.unwrap_err().code, McpErrorCode::InvalidRequest);
                            assert!(client.ping_with_cx(&cx).await.is_err());
                        } else {
                            observed.unwrap();
                        }
                        require_send(client.close_with_cx(&cx)).await.unwrap();
                        assert!(cx.checkpoint().is_ok());
                    }
                }
            });
        }
        mod cancellation_controls {
            use super::*;

            async fn connect(cx: &Cx, script: &str, release: &str) -> legacy::Client {
                let mut client = super::connect(cx, script, release).await;
                require_send(client.ensure_initialized_with_cx(cx))
                    .await
                    .unwrap();
                client
            }

            const WAIT_FOR_RELEASE: &str = r#"
turn=0
while [ ! -s "$1" ]; do
    turn=$((turn + 1))
    [ "$turn" -le 3000 ] || exit 90
    sleep 0.001
done
"#;

            fn exchange(
                script: &mut String,
                method: &str,
                checks: &str,
                result: &JsonValue,
                defer: bool,
            ) {
                script.push_str(&format!(
                    "read_request\n\
                     case \"$request\" in *'\"method\":\"{method}\"'*) ;; *) exit 91 ;; esac\n\
                     {checks}\n"
                ));
                if defer {
                    script.push_str(WAIT_FOR_RELEASE);
                }
                script.push_str(&format!(
                    "printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}}\\n' \"$id\" '{result}'\n"
                ));
            }

            fn finish_with_ping(script: &mut String) {
                exchange(script, "ping", "", &json!({}), false);
                script.push_str("while IFS= read -r unexpected; do exit 92; done\n");
            }

            async fn after_pending<F: Future + Send>(
                future: F,
                release: &DiscoveryRelease,
            ) -> F::Output {
                let mut future = Box::pin(require_send(future));
                let yielded = std::future::poll_fn(|task_cx| {
                    Poll::Ready(future.as_mut().poll(task_cx).is_pending())
                })
                .await;
                assert!(
                    yielded,
                    "an unanswered legacy operation must yield to its caller"
                );
                release.release();
                future.await
            }

            async fn control(
                client: &mut legacy::Client,
                cx: &Cx,
                cancellation: &legacy::McpRequestCancellation,
                method: &str,
            ) -> McpResult<()> {
                match method {
                    "resources/subscribe" => {
                        client
                            .subscribe_resource_with_cx_and_cancellation(
                                cx,
                                cancellation,
                                "test://watch",
                            )
                            .await
                    }
                    "resources/unsubscribe" => {
                        client
                            .unsubscribe_resource_with_cx_and_cancellation(
                                cx,
                                cancellation,
                                "test://watch",
                            )
                            .await
                    }
                    "logging/setLevel" => {
                        client
                            .set_log_level_with_cx_and_cancellation(
                                cx,
                                cancellation,
                                legacy::LogLevel::Debug,
                            )
                            .await
                    }
                    "ping" => client.ping_with_cx_and_cancellation(cx, cancellation).await,
                    _ => unreachable!(),
                }
            }

            #[test]
            fn legacy_async_control_tokens_are_local_and_notifications_are_retained() {
                run(|cx| async move {
                    let release = DiscoveryRelease::new();
                    let mut script = INITIALIZE.to_owned();
                    exchange(
                        &mut script,
                        "resources/subscribe",
                        r#"
case "$request" in *'"uri":"test://watch"'*) ;; *) exit 93 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"test://watch"}}'
"#,
                        &json!({}),
                        true,
                    );
                    exchange(
                        &mut script,
                        "logging/setLevel",
                        r#"
case "$request" in *'"level":"debug"'*) ;; *) exit 94 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"debug","logger":"legacy-peer","data":{"message":"logging enabled","retained":[1,2]}}}'
"#,
                        &json!({}),
                        false,
                    );
                    exchange(
                        &mut script,
                        "resources/unsubscribe",
                        r#"case "$request" in *'"uri":"test://watch"'*) ;; *) exit 95 ;; esac"#,
                        &json!({}),
                        false,
                    );
                    finish_with_ping(&mut script);

                    let mut client = connect(&cx, &script, release.path()).await;
                    let cancellation = legacy::McpRequestCancellation::new();
                    let cancelled = legacy::McpRequestCancellation::new();
                    cancelled.cancel();
                    for method in [
                        "resources/subscribe",
                        "logging/setLevel",
                        "resources/unsubscribe",
                        "ping",
                    ] {
                        let error = require_send(control(&mut client, &cx, &cancelled, method))
                            .await
                            .unwrap_err();
                        assert_eq!(error.code, McpErrorCode::RequestCancelled);
                    }
                    after_pending(
                        control(&mut client, &cx, &cancellation, "resources/subscribe"),
                        &release,
                    )
                    .await
                    .unwrap();
                    let notifications = client.take_server_notifications().unwrap();
                    let [legacy::ServerNotification::ResourceUpdated(updated)] =
                        notifications.as_slice()
                    else {
                        panic!("subscription acknowledgement must retain the preceding update");
                    };
                    assert_eq!(updated.uri, "test://watch");

                    require_send(control(&mut client, &cx, &cancellation, "logging/setLevel"))
                        .await
                        .unwrap();
                    let notifications = client.take_server_notifications().unwrap();
                    let [legacy::ServerNotification::Message(message)] = notifications.as_slice()
                    else {
                        panic!("logging acknowledgement must retain the preceding log message");
                    };
                    assert_eq!(message.level, legacy::LogLevel::Debug);
                    assert_eq!(message.logger.as_deref(), Some("legacy-peer"));
                    assert_eq!(
                        message.data,
                        json!({"message": "logging enabled", "retained": [1, 2]}),
                    );

                    require_send(control(
                        &mut client,
                        &cx,
                        &cancellation,
                        "resources/unsubscribe",
                    ))
                    .await
                    .unwrap();
                    assert!(client.take_server_notifications().unwrap().is_empty());
                    require_send(client.ping_with_cx_and_cancellation(&cx, &cancellation))
                        .await
                        .unwrap();
                    assert!(cx.checkpoint().is_ok());
                    client.close_with_cx(&cx).await.unwrap();
                });
            }

            #[test]
            fn legacy_async_token_controls_reject_nonempty_and_modern_acknowledgements() {
                run(|cx| async move {
                    for method in [
                        "resources/subscribe",
                        "resources/unsubscribe",
                        "logging/setLevel",
                        "ping",
                    ] {
                        for invalid in [
                            json!({"resultType": "complete"}),
                            json!({"unexpected": true}),
                        ] {
                            let mut script = INITIALIZE.to_owned();
                            exchange(&mut script, method, "", &invalid, false);
                            script.push_str("while IFS= read -r unexpected; do exit 96; done\n");
                            let mut client = connect(&cx, &script, "").await;
                            let cancellation = legacy::McpRequestCancellation::new();
                            let error =
                                require_send(control(&mut client, &cx, &cancellation, method))
                                    .await
                                    .unwrap_err();
                            assert_eq!(error.code, McpErrorCode::InvalidRequest);
                            assert!(client.ping_with_cx(&cx).await.is_err());
                            assert!(cx.checkpoint().is_ok());
                            client.close_with_cx(&cx).await.unwrap();
                        }
                    }
                });
            }

            #[test]
            fn legacy_async_tool_token_yields_and_preserves_tool_level_errors() {
                run(|cx| async move {
                    let release = DiscoveryRelease::new();
                    let mut script = INITIALIZE.to_owned();
                    let success = json!({
                        "content": [{"type": "text", "text": "legacy payload"}],
                        "_meta": {"retained": true},
                        "receipt": {"kind": "legacy"},
                    });
                    let tool_error = json!({
                        "content": [{"type": "text", "text": "tool reported failure"}],
                        "isError": true,
                    });
                    exchange(
                        &mut script,
                        "tools/call",
                        r#"
case "$request" in *'"name":"echo"'*) ;; *) exit 97 ;; esac
case "$request" in *'"arguments":{"message":"legacy payload"}'*) ;; *) exit 98 ;; esac
"#,
                        &success,
                        true,
                    );
                    exchange(
                        &mut script,
                        "tools/call",
                        r#"case "$request" in *'"name":"fail"'*) ;; *) exit 99 ;; esac"#,
                        &tool_error,
                        false,
                    );
                    finish_with_ping(&mut script);

                    let mut client = connect(&cx, &script, release.path()).await;
                    let cancellation = legacy::McpRequestCancellation::new();
                    let cancelled = legacy::McpRequestCancellation::new();
                    cancelled.cancel();
                    let error = require_send(client.call_tool_with_cx_and_cancellation(
                        &cx,
                        &cancelled,
                        "echo",
                        json!({"message": "legacy payload"}),
                    ))
                    .await
                    .unwrap_err();
                    assert_eq!(error.code, McpErrorCode::RequestCancelled);
                    let result: legacy::CallToolResult = after_pending(
                        client.call_tool_with_cx_and_cancellation(
                            &cx,
                            &cancellation,
                            "echo",
                            json!({"message": "legacy payload"}),
                        ),
                        &release,
                    )
                    .await
                    .unwrap();
                    assert!(!result.is_error);
                    assert_eq!(serde_json::to_value(result).unwrap(), success);
                    let result: legacy::CallToolResult =
                        require_send(client.call_tool_with_cx_and_cancellation(
                            &cx,
                            &cancellation,
                            "fail",
                            json!({}),
                        ))
                        .await
                        .unwrap();
                    assert!(result.is_error);
                    assert_eq!(serde_json::to_value(result).unwrap(), tool_error);
                    require_send(client.ping_with_cx_and_cancellation(&cx, &cancellation))
                        .await
                        .unwrap();
                    assert!(cx.checkpoint().is_ok());
                    client.close_with_cx(&cx).await.unwrap();
                });
            }

            #[test]
            fn legacy_async_tool_token_cancels_one_published_request_and_preserves_siblings() {
                run(|cx| async move {
                    let script = format!(
                        "{INITIALIZE}\n\
                         read_request\n\
                         case \"$request\" in *'\"method\":\"tools/call\"'*) ;; *) exit 100 ;; esac\n\
                         case \"$request\" in *'\"name\":\"wait\"'*) ;; *) exit 101 ;; esac\n\
                         pending_id=$id\n\
                         IFS= read -r cancelled || exit 102\n\
                         case \"$cancelled\" in *'\"method\":\"notifications/cancelled\"'*) ;; *) exit 103 ;; esac\n\
                         cancelled_id=$(printf '%s\\n' \"$cancelled\" | sed -n 's/.*\"requestId\":\\([0-9][0-9]*\\)[,}}].*/\\1/p')\n\
                         [ \"$cancelled_id\" = \"$pending_id\" ] || exit 104\n\
                         read_request\n\
                         case \"$request\" in *'\"method\":\"ping\"'*) ;; *) exit 105 ;; esac\n\
                         printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"late result\"}}]}}}}\\n' \"$pending_id\"\n\
                         printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{}}}}\\n' \"$id\"\n\
                         while IFS= read -r unexpected; do exit 106; done\n"
                    );
                    let mut client = connect(&cx, &script, "").await;
                    let cancellation = legacy::McpRequestCancellation::new();
                    let mut calling =
                        Box::pin(require_send(client.call_tool_with_cx_and_cancellation(
                            &cx,
                            &cancellation,
                            "wait",
                            json!({}),
                        )));
                    let yielded = std::future::poll_fn(|task_cx| {
                        Poll::Ready(calling.as_mut().poll(task_cx).is_pending())
                    })
                    .await;
                    assert!(yielded, "the peer retains this published request");
                    cancellation.cancel();
                    assert_eq!(
                        calling.await.unwrap_err().code,
                        McpErrorCode::RequestCancelled,
                    );
                    assert!(cx.checkpoint().is_ok());
                    // The strict peer expects exactly one cancellation for the
                    // published ID, then a fresh ping. A late result cannot
                    // replace the sibling's acknowledgement.
                    let sibling = legacy::McpRequestCancellation::new();
                    require_send(client.ping_with_cx_and_cancellation(&cx, &sibling))
                        .await
                        .unwrap();
                    assert!(cx.checkpoint().is_ok());
                    client.close_with_cx(&cx).await.unwrap();
                });
            }

            #[test]
            fn legacy_async_completion_preserves_explicit_request_progress_metadata() {
                run(|cx| async move {
                    let release = DiscoveryRelease::new();
                    let mut script = INITIALIZE.to_owned();
                    let expected = json!({
                        "completion": {"values": ["Ada", "Alice"], "total": 2, "hasMore": false},
                        "_meta": {"retained": "legacy"},
                    });
                    exchange(
                        &mut script,
                        "completion/complete",
                        r#"
case "$request" in *'"progressToken":"legacy completion /+=? marker"'*) ;; *) exit 107 ;; esac
case "$request" in *'"type":"ref/prompt"'*) ;; *) exit 108 ;; esac
case "$request" in *'"argument":{"name":"name","value":"A"}'*) ;; *) exit 109 ;; esac
case "$request" in *'"context":'*) exit 110 ;; esac
"#,
                        &expected,
                        true,
                    );
                    finish_with_ping(&mut script);

                    let mut client = connect(&cx, &script, release.path()).await;
                    let cancellation = legacy::McpRequestCancellation::new();
                    let cancelled = legacy::McpRequestCancellation::new();
                    cancelled.cancel();
                    let params = legacy::LegacyCompletionParams {
                        reference: legacy::LegacyCompletionReference::Prompt {
                            name: "greet".to_owned(),
                        },
                        argument: legacy::LegacyCompletionArgument {
                            name: "name".to_owned(),
                            value: "A".to_owned(),
                        },
                        meta: Some(legacy::RequestMeta {
                            progress_marker: Some(legacy::ProgressMarker::String(
                                "legacy completion /+=? marker".to_owned(),
                            )),
                        }),
                    };
                    let error =
                        require_send(client.complete_with_cx(&cx, &cancelled, params.clone()))
                            .await
                            .unwrap_err();
                    assert_eq!(error.code, McpErrorCode::RequestCancelled);
                    let result: legacy::LegacyCompletionResult = after_pending(
                        client.complete_with_cx(&cx, &cancellation, params),
                        &release,
                    )
                    .await
                    .unwrap();
                    assert_eq!(serde_json::to_value(result).unwrap(), expected);
                    require_send(client.ping_with_cx_and_cancellation(&cx, &cancellation))
                        .await
                        .unwrap();
                    assert!(cx.checkpoint().is_ok());
                    client.close_with_cx(&cx).await.unwrap();
                });
            }
        }
    }

    async fn collect(
        client: &mut modern::Client,
        cx: &Cx,
        cancellation: &modern::McpRequestCancellation,
        method: &str,
    ) -> McpResult<modern::CollectedCatalog> {
        let params = json!({"includeTags": ["visible"], "excludeTags": ["hidden"]});
        match method {
            "tools/list" => {
                client
                    .list_all_tools_with_cx(
                        cx,
                        cancellation,
                        serde_json::from_value(params).unwrap(),
                    )
                    .await
            }
            "resources/list" => {
                client
                    .list_all_resources_with_cx(
                        cx,
                        cancellation,
                        serde_json::from_value(params).unwrap(),
                    )
                    .await
            }
            "resources/templates/list" => {
                client
                    .list_all_resource_templates_with_cx(
                        cx,
                        cancellation,
                        serde_json::from_value(params).unwrap(),
                    )
                    .await
            }
            "prompts/list" => {
                client
                    .list_all_prompts_with_cx(
                        cx,
                        cancellation,
                        serde_json::from_value(params).unwrap(),
                    )
                    .await
            }
            _ => unreachable!(),
        }
    }

    async fn catalog_page(
        client: &mut modern::Client,
        cx: &Cx,
        cancellation: &modern::McpRequestCancellation,
        method: &str,
        params: JsonValue,
    ) -> McpResult<JsonValue> {
        let result = match method {
            "tools/list" => serde_json::to_value(
                client
                    .list_tools_with_cx(cx, cancellation, serde_json::from_value(params).unwrap())
                    .await?,
            ),
            "resources/list" => serde_json::to_value(
                client
                    .list_resources_with_cx(
                        cx,
                        cancellation,
                        serde_json::from_value(params).unwrap(),
                    )
                    .await?,
            ),
            "resources/templates/list" => serde_json::to_value(
                client
                    .list_resource_templates_with_cx(
                        cx,
                        cancellation,
                        serde_json::from_value(params).unwrap(),
                    )
                    .await?,
            ),
            "prompts/list" => serde_json::to_value(
                client
                    .list_prompts_with_cx(cx, cancellation, serde_json::from_value(params).unwrap())
                    .await?,
            ),
            _ => unreachable!(),
        };
        result.map_err(|error| fastmcp_rust::McpError::internal_error(error.to_string()))
    }

    #[test]
    fn modern_async_catalog_pages_cache_without_traversing_or_losing_filters() {
        run(|cx| async move {
            const CURSOR: &str = " opaque /+=? token ";
            let catalogs = [
                (
                    "tools/list",
                    "tools",
                    json!({"name": "echo", "inputSchema": {"type": "object"}}),
                ),
                (
                    "resources/list",
                    "resources",
                    json!({"name": "source", "uri": "test://source"}),
                ),
                (
                    "resources/templates/list",
                    "resourceTemplates",
                    json!({"name": "source", "uriTemplate": "test://source/{name}"}),
                ),
                ("prompts/list", "prompts", json!({"name": "greet"})),
            ];
            let mut script = DISCOVER.to_owned();
            for (method, field, item) in &catalogs {
                for step in 0..3 {
                    let include = if step == 1 { "alternate" } else { "visible" };
                    script.push_str(&format!(
                        "read_request\n\
                         case \"$request\" in *'\"method\":\"{method}\"'*) ;; *) exit 90 ;; esac\n\
                         case \"$request\" in *'\"includeTags\":[\"{include}\"]'*) ;; *) exit 91 ;; esac\n\
                         case \"$request\" in *'\"excludeTags\":[\"hidden\"]'*) ;; *) exit 92 ;; esac\n"
                    ));
                    if step == 2 {
                        script.push_str(
                            "case \"$request\" in *'\"cursor\":\" opaque /+=? token \"'*) ;; *) exit 93 ;; esac\n",
                        );
                    } else {
                        script.push_str("case \"$request\" in *'\"cursor\":'*) exit 94 ;; esac\n");
                    }
                    let mut result = json!({
                        "resultType": "complete",
                        "ttlMs": if step == 2 { 0 } else { 60000 },
                        "cacheScope": "private",
                    });
                    result[*field] = if step == 1 { json!([]) } else { json!([item]) };
                    if step == 0 {
                        result["nextCursor"] = json!(CURSOR);
                    }
                    script.push_str(&format!(
                        "printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{result}}}\\n' \"$id\"\n"
                    ));
                }
            }
            script.push_str("while IFS= read -r unexpected; do exit 95; done\n");
            let mut client = connect(&cx, &script, modern::ClientBuilder::new()).await;
            let cancellation = modern::McpRequestCancellation::new();
            for (method, field, _) in catalogs {
                let params = json!({"includeTags": ["visible"], "excludeTags": ["hidden"]});
                let first = require_send(catalog_page(
                    &mut client,
                    &cx,
                    &cancellation,
                    method,
                    params.clone(),
                ))
                .await
                .unwrap();
                assert_eq!(first[field].as_array().unwrap().len(), 1);
                assert_eq!(first["nextCursor"], json!(CURSOR));
                let hits = client.final_result_cache_stats().hits;
                let cached = require_send(catalog_page(
                    &mut client,
                    &cx,
                    &cancellation,
                    method,
                    params.clone(),
                ))
                .await
                .unwrap();
                assert_eq!(cached[field], first[field]);
                assert_eq!(cached["nextCursor"], first["nextCursor"]);
                assert_eq!(client.final_result_cache_stats().hits, hits + 1);

                // Changing only the caller's cancellation state refuses a hit
                // without sending a request or consuming the retained page.
                let cancelled = modern::McpRequestCancellation::new();
                cancelled.cancel();
                let error = require_send(catalog_page(
                    &mut client,
                    &cx,
                    &cancelled,
                    method,
                    params.clone(),
                ))
                .await
                .unwrap_err();
                assert_eq!(error.code, fastmcp_rust::McpErrorCode::RequestCancelled);

                // Changing only the semantic tag filter must contact the peer;
                // the empty result cannot be supplied by the warm visible page.
                let mut alternate = params.clone();
                alternate["includeTags"] = json!(["alternate"]);
                let changed = require_send(catalog_page(
                    &mut client,
                    &cx,
                    &cancellation,
                    method,
                    alternate,
                ))
                .await
                .unwrap();
                assert!(changed[field].as_array().unwrap().is_empty());

                let mut next = params;
                next["cursor"] = json!(CURSOR);
                let last =
                    require_send(catalog_page(&mut client, &cx, &cancellation, method, next))
                        .await
                        .unwrap();
                assert_eq!(last[field].as_array().unwrap().len(), 1);
                assert!(last.get("nextCursor").is_none());
            }
            client.close_with_cx(&cx).await.unwrap();
        });
    }

    fn retained_number(extras: &modern::UnknownResultMembers, name: &str) -> String {
        let member = extras
            .members()
            .iter()
            .find(|member| member.name == name)
            .unwrap();
        let modern::ExactJsonValue::Number(number) = &member.value else {
            panic!("the exact numeric result sibling must stay numeric");
        };
        number.clone()
    }

    #[test]
    fn modern_async_catalogs_preserve_complete_pages_and_opaque_cursors() {
        run(|cx| async move {
            let mut script = DISCOVER.to_owned();
            for (method, field, item) in [
                (
                    "tools/list",
                    "tools",
                    json!({"name": "echo", "inputSchema": {"type": "object"}}),
                ),
                (
                    "resources/list",
                    "resources",
                    json!({"name": "source", "uri": "test://source"}),
                ),
                (
                    "resources/templates/list",
                    "resourceTemplates",
                    json!({"name": "source", "uriTemplate": "test://source/{name}"}),
                ),
                ("prompts/list", "prompts", json!({"name": "greet"})),
            ] {
                for index in 0..3 {
                    script.push_str(&format!(
                        "read_request\n\
                         case \"$request\" in *'\"method\":\"{method}\"'*) ;; *) exit 20 ;; esac\n\
                         case \"$request\" in *'\"includeTags\":[\"visible\"]'*) ;; *) exit 21 ;; esac\n\
                         case \"$request\" in *'\"excludeTags\":[\"hidden\"]'*) ;; *) exit 22 ;; esac\n"
                    ));
                    script.push_str(match index {
                        0 => "case \"$request\" in *'\"cursor\":'*) exit 23 ;; esac\n",
                        1 => "case \"$request\" in *'\"cursor\":\"\"'*) ;; *) exit 24 ;; esac\n",
                        _ => "case \"$request\" in *'\"cursor\":\" opaque /+=? token \"'*) ;; *) exit 25 ;; esac\n",
                    });
                    let mut result = json!({
                        "cacheScope": if method == "tools/list" { "public" } else { "private" },
                    });
                    result[field] = if index == 1 {
                        json!([])
                    } else {
                        json!([item.clone()])
                    };
                    // A diagnosed absent discriminator remains attached to its
                    // own page, just like the page's TTL and unknown siblings.
                    if index != 1 {
                        result["resultType"] = json!("complete");
                    }
                    if index < 2 {
                        result["nextCursor"] = json!(if index == 0 {
                            ""
                        } else {
                            " opaque /+=? token "
                        });
                    }
                    let prefix = result.to_string();
                    let ttl = ["1.200e3", "0", "9.000e2"][index];
                    let result = format!(
                        "{},\"ttlMs\":{ttl},\"vendorExact\":922337203685477580812345678901234567890,\"vendorDecimal\":1.2300e+400}}",
                        prefix.strip_suffix('}').unwrap(),
                    );
                    script.push_str(&format!(
                        "printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{result}}}\\n' \"$id\"\n"
                    ));
                }
            }
            script.push_str("while IFS= read -r unexpected; do exit 26; done\n");
            let mut client = connect(&cx, &script, modern::ClientBuilder::new()).await;
            let cancellation = modern::McpRequestCancellation::new();
            for (method, field) in [
                ("tools/list", "tools"),
                ("resources/list", "resources"),
                ("resources/templates/list", "resourceTemplates"),
                ("prompts/list", "prompts"),
            ] {
                let catalog = require_send(collect(&mut client, &cx, &cancellation, method))
                    .await
                    .unwrap();
                assert_eq!(catalog.method(), method);
                assert_eq!(catalog.item_count(), 2);
                let pages: &[modern::FinalCoreResult] = catalog.pages();
                assert_eq!(pages.len(), 3);
                for (index, page) in pages.iter().enumerate() {
                    assert_eq!(page.method(), method);
                    let (payload, ttl, scope, extras, diagnosed) = match page {
                        modern::FinalCoreResult::ToolsList { result, diagnostic } => (
                            serde_json::to_value(&result.payload).unwrap(),
                            result.payload.ttl_ms.as_str(),
                            result.payload.cache_scope,
                            &result.extras,
                            diagnostic.is_some(),
                        ),
                        modern::FinalCoreResult::ResourcesList { result, diagnostic } => (
                            serde_json::to_value(&result.payload).unwrap(),
                            result.payload.ttl_ms.as_str(),
                            result.payload.cache_scope,
                            &result.extras,
                            diagnostic.is_some(),
                        ),
                        modern::FinalCoreResult::ResourceTemplatesList { result, diagnostic } => (
                            serde_json::to_value(&result.payload).unwrap(),
                            result.payload.ttl_ms.as_str(),
                            result.payload.cache_scope,
                            &result.extras,
                            diagnostic.is_some(),
                        ),
                        modern::FinalCoreResult::PromptsList { result, diagnostic } => (
                            serde_json::to_value(&result.payload).unwrap(),
                            result.payload.ttl_ms.as_str(),
                            result.payload.cache_scope,
                            &result.extras,
                            diagnostic.is_some(),
                        ),
                        _ => panic!("the sealed collection must retain its exact catalog family"),
                    };
                    assert_eq!(
                        payload[field].as_array().unwrap().len(),
                        usize::from(index != 1)
                    );
                    assert_eq!(ttl, ["1.200e3", "0", "9.000e2"][index]);
                    assert_eq!(
                        scope,
                        if method == "tools/list" {
                            modern::CacheScope::Public
                        } else {
                            modern::CacheScope::Private
                        },
                    );
                    assert_eq!(diagnosed, index == 1);
                    let expected_cursor = match index {
                        0 => Some(json!("")),
                        1 => Some(json!(" opaque /+=? token ")),
                        _ => None,
                    };
                    assert_eq!(payload.get("nextCursor"), expected_cursor.as_ref());
                    assert_eq!(
                        retained_number(extras, "vendorExact"),
                        "922337203685477580812345678901234567890"
                    );
                    assert_eq!(retained_number(extras, "vendorDecimal"), "1.2300e+400");
                }
                let owned_pages: Vec<modern::FinalCoreResult> = catalog.into_pages();
                assert_eq!(owned_pages.len(), 3);
            }
            client.close_with_cx(&cx).await.unwrap();
        });
    }

    #[test]
    fn modern_async_catalog_error_returns_no_partial_collection_and_allows_reuse() {
        run(|cx| async move {
            let script = [DISCOVER, r#"
read_request
case "$request" in *'"method":"tools/list"'*) ;; *) exit 30 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","tools":[{"name":"partial","inputSchema":{"type":"object"}}],"nextCursor":"continuation","ttlMs":0,"cacheScope":"private"}}\n' "$id"
read_request
case "$request" in *'"method":"tools/list"'*'"cursor":"continuation"'*|*'"cursor":"continuation"'*'"method":"tools/list"'*) ;; *) exit 31 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"continuation refused","data":{"page":2}}}\n' "$id"
read_request
case "$request" in *'"method":"server/discover"'*) ;; *) exit 32 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$id" "$1"
read_request
case "$request" in *'"method":"prompts/list"'*) ;; *) exit 33 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","prompts":[{"name":"healthy"}],"ttlMs":0,"cacheScope":"private"}}\n' "$id"
while IFS= read -r unexpected; do exit 34; done
"#].concat();
            let mut client = connect(&cx, &script, modern::ClientBuilder::new()).await;
            let cancelled = modern::McpRequestCancellation::new();
            cancelled.cancel();
            let error = require_send(collect(&mut client, &cx, &cancelled, "tools/list"))
                .await
                .unwrap_err();
            assert_eq!(error.code, fastmcp_rust::McpErrorCode::RequestCancelled);
            let cancellation = modern::McpRequestCancellation::new();
            let error = require_send(collect(&mut client, &cx, &cancellation, "tools/list"))
                .await
                .unwrap_err();
            assert_eq!(error.code, fastmcp_rust::McpErrorCode::InternalError);
            assert_eq!(error.message, "continuation refused");
            assert_eq!(error.data, Some(json!({"page": 2})));
            require_send(client.ping_with_cx(&cx, &cancellation))
                .await
                .unwrap();
            let recovered = require_send(collect(&mut client, &cx, &cancellation, "prompts/list"))
                .await
                .unwrap();
            assert_eq!(recovered.item_count(), 1);
            assert_eq!(recovered.pages().len(), 1);
            assert!(cx.checkpoint().is_ok());
            client.close_with_cx(&cx).await.unwrap();
        });
    }

    async fn content(
        client: &mut modern::Client,
        cx: &Cx,
        cancellation: &modern::McpRequestCancellation,
        method: &str,
    ) -> McpResult<modern::FinalCoreResult> {
        match method {
            "tools/call" => {
                client
                    .call_tool_result_with_cx(
                        cx,
                        cancellation,
                        "echo",
                        json!({"subject": "retained"}),
                    )
                    .await
            }
            "resources/read" => {
                client
                    .read_resource_result_with_cx(cx, cancellation, "test://retained")
                    .await
            }
            "prompts/get" => {
                client
                    .get_prompt_result_with_cx(
                        cx,
                        cancellation,
                        "greet",
                        HashMap::from([("subject".to_owned(), "retained".to_owned())]),
                    )
                    .await
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn modern_async_content_follows_yielding_handlers_and_preserves_unhandled_input() {
        fn operation_response<'cx>(
            caller: &'cx Cx,
            input: &'cx modern::InputRequiredResult,
            calls: Arc<AtomicUsize>,
            sibling_ran: Arc<AtomicBool>,
            worker: std::thread::ThreadId,
        ) -> modern::MrtrResponderFuture<'cx> {
            Box::pin(async move {
                assert_eq!(std::thread::current().id(), worker);
                assert!(caller.blocking_pool_handle().is_none());
                calls.fetch_add(1, Ordering::AcqRel);
                while !sibling_ran.load(Ordering::Acquire) {
                    asupersync::runtime::yield_now().await;
                }
                asupersync::time::sleep(caller.now(), Duration::from_millis(1)).await;
                assert_eq!(input.request_state(), Some("opaque continuation"));
                assert!(input.input_requests().unwrap().get("roots-input").is_some());
                Ok(modern::MrtrInputResponses::from([(
                    "roots-input".to_owned(),
                    json!({"roots": []}),
                )]))
            })
        }

        async fn operation_content<F>(
            client: &mut modern::Client,
            cx: &Cx,
            cancellation: &modern::McpRequestCancellation,
            method: &str,
            respond: F,
        ) -> modern::McpResult<modern::FinalCoreResult>
        where
            F: for<'a> FnMut(&'a Cx, &'a modern::InputRequiredResult) -> modern::MrtrResponderFuture<'a>,
        {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            match method {
                "tools/call" => {
                    client
                        .call_tool_with_async_mrtr_retry(
                            cx, cancellation, deadline, "echo", json!({"subject": "retained"}), respond,
                        )
                        .await
                }
                "resources/read" => {
                    client
                        .read_resource_with_async_mrtr_retry(
                            cx, cancellation, deadline, "test://retained", respond,
                        )
                        .await
                }
                "prompts/get" => {
                    client
                        .get_prompt_with_async_mrtr_retry(
                            cx, cancellation, deadline, "greet",
                            HashMap::from([("subject".to_owned(), "retained".to_owned())]),
                            respond,
                        )
                        .await
                }
                _ => unreachable!(),
            }
        }

        for mode in ["unhandled", "installed", "operation-local"] {
            let installed = mode == "installed";
            let operation_local = mode == "operation-local";
            let handled = mode != "unhandled";
            run(|cx| async move {
                let mut script = DISCOVER.to_owned();
                for (method, original, completed) in [
                    (
                        "tools/call",
                        r#""name":"echo""#,
                        r#"{"resultType":"complete","content":[{"type":"text","text":"tool complete"}],"vendorDecimal":1.2300e+400}"#,
                    ),
                    (
                        "resources/read",
                        r#""uri":"test://retained""#,
                        r#"{"resultType":"complete","contents":[{"uri":"test://retained","text":"resource complete"}],"ttlMs":0,"cacheScope":"private","vendorDecimal":1.2300e+400}"#,
                    ),
                    (
                        "prompts/get",
                        r#""name":"greet""#,
                        r#"{"resultType":"complete","messages":[{"role":"user","content":{"type":"text","text":"prompt complete"}}],"vendorDecimal":1.2300e+400}"#,
                    ),
                ] {
                    script.push_str(&format!(
                        "read_request\n\
                         case \"$request\" in *'\"method\":\"{method}\"'*) ;; *) exit 40 ;; esac\n\
                         case \"$request\" in *'{original}'*) ;; *) exit 41 ;; esac\n\
                         case \"$request\" in *'requestState'*|*'inputResponses'*|*'io.modelcontextprotocol/tasks'*) exit 42 ;; esac\n\
                         printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"resultType\":\"input_required\",\"inputRequests\":{{\"roots-input\":{{\"method\":\"roots/list\"}}}},\"requestState\":\"opaque continuation\",\"vendorDecimal\":1.2300e+400}}}}\\n' \"$id\"\n"
                    ));
                    if handled {
                        script.push_str(&format!(
                            "read_request\n\
                             case \"$request\" in *'\"method\":\"{method}\"'*) ;; *) exit 43 ;; esac\n\
                             case \"$request\" in *'{original}'*) ;; *) exit 44 ;; esac\n\
                             case \"$request\" in *'\"requestState\":\"opaque continuation\"'*) ;; *) exit 45 ;; esac\n\
                             case \"$request\" in *'\"roots-input\":{{\"roots\":[]}}'*) ;; *) exit 46 ;; esac\n\
                             case \"$request\" in *'io.modelcontextprotocol/tasks'*) exit 47 ;; esac\n\
                             printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{completed}}}\\n' \"$id\"\n"
                        ));
                    }
                }
                script.push_str(r#"
read_request
case "$request" in *'"method":"completion/complete"'*) ;; *) exit 48 ;; esac
case "$request" in *'"value":"A"'*) ;; *) exit 49 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","completion":{"values":["Ada"],"total":1,"hasMore":false}}}\n' "$id"
while IFS= read -r unexpected; do exit 50; done
"#);
                let calls = Arc::new(AtomicUsize::new(0));
                let sibling_ran = Arc::new(AtomicBool::new(false));
                let worker = std::thread::current().id();
                let builder = if installed {
                    let calls = Arc::clone(&calls);
                    let sibling_ran = Arc::clone(&sibling_ran);
                    modern::ClientBuilder::new().modern_reverse_request_handlers(
                        modern::ReverseRequestHandlers::new().with_modern_roots_list(
                            move |cx, _, _| {
                                let calls = Arc::clone(&calls);
                                let sibling_ran = Arc::clone(&sibling_ran);
                                Box::pin(async move {
                                    assert_eq!(std::thread::current().id(), worker);
                                    assert!(cx.blocking_pool_handle().is_none());
                                    calls.fetch_add(1, Ordering::AcqRel);
                                    while !sibling_ran.load(Ordering::Acquire) {
                                        asupersync::runtime::yield_now().await;
                                    }
                                    asupersync::time::sleep(cx.now(), Duration::from_millis(1))
                                        .await;
                                    serde_json::from_value(json!({"roots": []})).map_err(|_| {
                                        modern::McpError::internal_error("invalid roots fixture")
                                    })
                                })
                            },
                        ),
                    )
                } else if operation_local {
                    modern::ClientBuilder::new()
                        .capabilities(serde_json::from_value(json!({"roots": {}})).unwrap())
                } else {
                    modern::ClientBuilder::new()
                };
                let mut client = connect(&cx, &script, builder).await;
                let mut sibling = handled.then(|| {
                    let calls = Arc::clone(&calls);
                    let sibling_ran = Arc::clone(&sibling_ran);
                    cx.spawn(move |_| async move {
                        while calls.load(Ordering::Acquire) == 0 {
                            asupersync::runtime::yield_now().await;
                        }
                        assert_eq!(std::thread::current().id(), worker);
                        sibling_ran.store(true, Ordering::Release);
                    })
                    .unwrap()
                });
                let cancellation = modern::McpRequestCancellation::new();
                for method in ["tools/call", "resources/read", "prompts/get"] {
                    let result = if operation_local {
                        let calls = Arc::clone(&calls);
                        let sibling_ran = Arc::clone(&sibling_ran);
                        require_send(operation_content(
                            &mut client,
                            &cx,
                            &cancellation,
                            method,
                            move |caller, input| {
                                operation_response(
                                    caller,
                                    input,
                                    Arc::clone(&calls),
                                    Arc::clone(&sibling_ran),
                                    worker,
                                )
                            },
                        ))
                        .await
                    } else {
                        require_send(content(&mut client, &cx, &cancellation, method)).await
                    }
                    .unwrap();
                    assert_eq!(result.method(), method);
                    let extras = match &result {
                        modern::FinalCoreResult::ToolsCall { result, .. } if handled => {
                            assert_eq!(
                                result.payload.content,
                                vec![modern::ContentBlock::text("tool complete")]
                            );
                            &result.extras
                        }
                        modern::FinalCoreResult::ResourcesRead { result, .. } if handled => {
                            assert_eq!(
                                serde_json::to_value(&result.payload.contents).unwrap(),
                                json!([{"uri": "test://retained", "text": "resource complete"}])
                            );
                            &result.extras
                        }
                        modern::FinalCoreResult::PromptsGet { result, .. } if handled => {
                            assert_eq!(
                                serde_json::to_value(&result.payload.messages).unwrap(),
                                json!([{"role": "user", "content": {"type": "text", "text": "prompt complete"}}])
                            );
                            &result.extras
                        }
                        modern::FinalCoreResult::ToolsCallInputRequired { result, .. }
                        | modern::FinalCoreResult::ResourcesReadInputRequired { result, .. }
                        | modern::FinalCoreResult::PromptsGetInputRequired { result, .. }
                            if !handled =>
                        {
                            assert_eq!(result.request_state(), Some("opaque continuation"));
                            assert!(
                                result
                                    .input_requests()
                                    .unwrap()
                                    .get("roots-input")
                                    .is_some()
                            );
                            &result.extras
                        }
                        _ => panic!(
                            "the public method must preserve the selected final result algebra"
                        ),
                    };
                    assert_eq!(retained_number(extras, "vendorDecimal"), "1.2300e+400");
                }
                if let Some(sibling) = sibling.as_mut() {
                    sibling.join(&cx).await.unwrap();
                }
                assert_eq!(calls.load(Ordering::Acquire), if handled { 3 } else { 0 });
                let completion = require_send(
                    client.complete_with_cx(
                        &cx,
                        &cancellation,
                        serde_json::from_value(json!({
                            "ref": {"type": "ref/prompt", "name": "greet"},
                            "argument": {"name": "person", "value": "A"},
                        }))
                        .unwrap(),
                    ),
                )
                .await
                .unwrap();
                assert_eq!(
                    serde_json::to_value(completion).unwrap(),
                    json!({
                        "completion": {"values": ["Ada"], "total": 1, "hasMore": false},
                    })
                );
                client.close_with_cx(&cx).await.unwrap();
            });
        }
    }

    #[test]
    fn modern_async_subscription_survives_dropped_wait_and_ordinary_requests() {
        run(|cx| async move {
            let script = [DISCOVER, r#"
read_request
case "$request" in *'"method":"subscriptions/listen"'*) ;; *) exit 60 ;; esac
case "$request" in *'"toolsListChanged":true'*) ;; *) exit 61 ;; esac
listener=$id
read_request
case "$request" in *'"method":"server/discover"'*) ;; *) exit 62 ;; esac
printf '{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":%s},"notifications":{"toolsListChanged":true}}}\n' "$listener"
printf '{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":%s}}}\n' "$listener"
printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$id" "$1"
read_request
case "$request" in *'"method":"server/discover"'*) ;; *) exit 63 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":%s}}}\n' "$listener" "$listener"
printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$id" "$1"
read_request
case "$request" in *'"method":"server/discover"'*) ;; *) exit 64 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$id" "$1"
while IFS= read -r unexpected; do exit 65; done
"#].concat();
            let mut client = connect(&cx, &script, modern::ClientBuilder::new()).await;
            let cancellation = modern::McpRequestCancellation::new();
            require_send(client.open_subscriptions_listener_with_cx(
                &cx,
                &cancellation,
                modern::SubscriptionFilter {
                    tools_list_changed: Some(true),
                    ..modern::SubscriptionFilter::default()
                },
            ))
            .await
            .unwrap();
            require_send(client.ping_with_cx(&cx, &cancellation))
                .await
                .unwrap();
            assert!(matches!(
                require_send(client.next_subscription_event_with_cx(&cx, &cancellation)).await.unwrap(),
                modern::StdioSubscriptionEvent::Acknowledged(filter)
                    if filter.tools_list_changed == Some(true)
            ));
            assert!(matches!(
                require_send(client.next_subscription_event_with_cx(&cx, &cancellation))
                    .await
                    .unwrap(),
                modern::StdioSubscriptionEvent::Notification(
                    modern::ServerNotification::ToolsListChanged(Some(_))
                )
            ));
            assert!(client.take_server_notifications().is_empty());
            let mut waiting = Box::pin(require_send(
                client.next_subscription_event_with_cx(&cx, &cancellation),
            ));
            assert!(
                std::future::poll_fn(|task_cx| Poll::Ready(waiting.as_mut().poll(task_cx)))
                    .await
                    .is_pending()
            );
            drop(waiting);
            require_send(client.ping_with_cx(&cx, &cancellation))
                .await
                .unwrap();
            assert!(matches!(
                require_send(client.next_subscription_event_with_cx(&cx, &cancellation))
                    .await
                    .unwrap(),
                modern::StdioSubscriptionEvent::Terminal
            ));
            require_send(client.ping_with_cx(&cx, &cancellation))
                .await
                .unwrap();
            assert!(cx.checkpoint().is_ok());
            client.close_with_cx(&cx).await.unwrap();
        });
    }

    #[cfg(feature = "tasks")]
    #[test]
    fn modern_async_tasks_preserve_outcomes_inputs_and_live_listener_ownership() {
        run(|cx| async move {
            let script = [DISCOVER, r#"
read_request
case "$request" in *'"method":"tools/call"'*) ;; *) exit 70 ;; esac
case "$request" in *'"name":"durable-tool"'*) ;; *) exit 71 ;; esac
case "$request" in *'"io.modelcontextprotocol/tasks":{}'*) ;; *) exit 72 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"task","taskId":"task-public","status":"working","createdAt":"2026-07-28T12:00:00Z","lastUpdatedAt":"2026-07-28T12:00:00Z","ttlMs":null}}\n' "$id"
read_request
case "$request" in *'"method":"subscriptions/listen"'*) ;; *) exit 73 ;; esac
case "$request" in *'"taskIds":["task-public"]'*) ;; *) exit 74 ;; esac
listener=$id
read_request
case "$request" in *'"method":"tasks/get"'*) ;; *) exit 75 ;; esac
case "$request" in *'"taskId":"task-public"'*) ;; *) exit 76 ;; esac
printf '{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":%s},"notifications":{"taskIds":["task-public"]}}}\n' "$listener"
printf '{"jsonrpc":"2.0","method":"notifications/tasks","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":%s},"taskId":"task-public","status":"working","createdAt":"2026-07-28T12:00:00Z","lastUpdatedAt":"2026-07-28T12:00:00Z","ttlMs":null}}\n' "$listener"
printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","taskId":"task-public","status":"input_required","createdAt":"2026-07-28T12:00:00Z","lastUpdatedAt":"2026-07-28T12:00:00Z","ttlMs":null,"inputRequests":{"need-roots":{"method":"roots/list"}}}}\n' "$id"
read_request
case "$request" in *'"method":"tasks/update"'*) ;; *) exit 77 ;; esac
case "$request" in *'"taskId":"task-public"'*) ;; *) exit 78 ;; esac
case "$request" in *'"inputResponses":{"need-roots":{"roots":[]}}'*) ;; *) exit 79 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","receipt":"input accepted"}}\n' "$id"
read_request
case "$request" in *'"method":"tasks/cancel"'*) ;; *) exit 80 ;; esac
case "$request" in *'"taskId":"task-public"'*) ;; *) exit 81 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","receipt":"cancellation requested"}}\n' "$id"
read_request
case "$request" in *'"method":"tasks/get"'*) ;; *) exit 82 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":%s}}}\n' "$listener" "$listener"
printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","taskId":"task-public","status":"completed","createdAt":"2026-07-28T12:00:00Z","lastUpdatedAt":"2026-07-28T12:00:00Z","ttlMs":null,"result":{"content":[{"type":"text","text":"completed before cancellation"}],"vendorExact":922337203685477580812345678901234567890,"vendorDecimal":1.2300e+400}}}\n' "$id"
read_request
case "$request" in *'"method":"server/discover"'*) ;; *) exit 83 ;; esac
printf '{"jsonrpc":"2.0","id":%s,"result":%s}\n' "$id" "$1"
while IFS= read -r unexpected; do exit 84; done
"#].concat();
            let extensions =
                std::collections::BTreeMap::from([(modern::TASKS_EXTENSION.to_owned(), json!({}))]);
            let discovery = discovery_with_extensions(extensions.clone());
            let mut client = modern::ClientBuilder::new()
                .capabilities(modern::ClientCapabilities {
                    extensions: Some(extensions),
                    ..modern::ClientCapabilities::default()
                })
                .max_retries(0)
                .request_timeout_policy(
                    modern::RequestTimeoutPolicy::new(
                        Duration::from_secs(5),
                        Duration::from_secs(5),
                    )
                    .unwrap(),
                )
                .connect_stdio_with_cx(&cx, "sh", &["-c", &script, "public-tasks-peer", &discovery])
                .await
                .unwrap();
            let cancellation = modern::McpRequestCancellation::new();
            let outcome = require_send(client.call_tool_outcome_with_cx(
                &cx,
                &cancellation,
                "durable-tool",
                json!({"work": "retained"}),
            ))
            .await
            .unwrap();
            let modern::FinalToolCallOutcome::Task(created) = outcome else {
                panic!("the public API must retain the task outcome, not project it to content");
            };
            assert!(matches!(&created.task, modern::FinalTask::Working(_)));
            let task_id = created.task.base().task_id.clone();
            assert_eq!(task_id.as_str(), "task-public");
            let mut filter = modern::SubscriptionFilter::default();
            modern::set_task_subscription_ids(&mut filter, vec![task_id.clone()]).unwrap();
            require_send(client.open_final_task_subscription_listener_with_cx(
                &cx,
                &cancellation,
                filter,
            ))
            .await
            .unwrap();
            let input = require_send(client.get_task_with_cx(&cx, &cancellation, task_id.clone()))
                .await
                .unwrap();
            assert!(matches!(
                &input.task,
                modern::FinalTask::InputRequired { .. }
            ));
            assert!(matches!(
                require_send(client.next_final_task_subscription_event_with_cx(&cx, &cancellation)).await.unwrap(),
                modern::StdioTaskSubscriptionEvent::Acknowledged(filter)
                    if modern::task_subscription_ids(&filter).unwrap() == Some(vec![task_id.clone()])
            ));
            assert!(matches!(
                require_send(client.next_final_task_subscription_event_with_cx(&cx, &cancellation)).await.unwrap(),
                modern::StdioTaskSubscriptionEvent::Notification(notification)
                    if notification.params.task.base().task_id == task_id
            ));
            assert!(client.take_server_notifications().is_empty());
            let invalid = serde_json::from_value(json!({
                "need-roots": {"action": "accept"},
            }))
            .unwrap();
            let error =
                require_send(client.update_task_with_cx(&cx, &cancellation, &input.task, invalid))
                    .await
                    .unwrap_err();
            assert_eq!(error.code, fastmcp_rust::McpErrorCode::InvalidParams);
            let updated = require_send(client.update_task_with_cx(
                &cx,
                &cancellation,
                &input.task,
                serde_json::from_value(json!({"need-roots": {"roots": []}})).unwrap(),
            ))
            .await
            .unwrap();
            assert_eq!(updated.additional["receipt"], "input accepted");
            let cancelled =
                require_send(client.cancel_task_with_cx(&cx, &cancellation, task_id.clone()))
                    .await
                    .unwrap();
            assert_eq!(cancelled.additional["receipt"], "cancellation requested");
            // The acknowledgement does not turn a cancellation request into
            // a terminal Task. A racing completion remains its own outcome.
            let completed =
                require_send(client.get_task_with_cx(&cx, &cancellation, task_id.clone()))
                    .await
                    .unwrap();
            assert_eq!(completed.task.base().task_id, task_id);
            let modern::FinalTask::Completed { result, .. } = &completed.task else {
                panic!("task completion must survive an earlier cancellation acknowledgement");
            };
            let encoded = serde_json::to_string(result).unwrap();
            assert!(encoded.contains(r#""text":"completed before cancellation""#));
            assert!(encoded.contains(r#""vendorExact":922337203685477580812345678901234567890"#));
            assert!(encoded.contains(r#""vendorDecimal":1.2300e+400"#));
            assert!(matches!(
                require_send(client.next_final_task_subscription_event_with_cx(&cx, &cancellation))
                    .await
                    .unwrap(),
                modern::StdioTaskSubscriptionEvent::Terminal
            ));
            require_send(client.ping_with_cx(&cx, &cancellation))
                .await
                .unwrap();
            client.close_with_cx(&cx).await.unwrap();
        });
    }
}
