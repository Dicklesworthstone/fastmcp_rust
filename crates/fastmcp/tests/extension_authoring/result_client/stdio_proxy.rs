//! Typed gateways over real native subprocesses and the shipped memory server.

use super::*;
use std::future::Future;
use std::path::{Path, PathBuf};

use fastmcp_rust::extensions::authoring::ExtensionStdioUpstream;

const EVENT: &str = "com.example/request-scaled";
const OWNER: &str = "com.example/request-id";

fn discovery_response(multiplier: u32) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "resultType": "complete",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {
                "extensions": {(EXTENSION): {"version": 1, "multiplier": multiplier}}
            },
            "ttlMs": 0,
            "cacheScope": "private"
        }
    }))
    .unwrap()
}

fn run<F: Future<Output = ()>>(exercise: impl FnOnce(Cx) -> F) {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), exercise(cx))
            .await
            .expect("native stdio gateway and cleanup must settle on the caller runtime");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

async fn connect_upstream(
    cx: &Cx,
    script: &str,
    declaration: ExtensionRegistration,
) -> ExtensionStdioUpstream {
    modern::ClientBuilder::new()
        .client_info("typed-stdio-proxy-upstream", "1")
        .auto_initialize(false)
        .connect_extension_stdio_upstream_with_cx(
            cx,
            "sh",
            &["-c", script],
            declaration,
            &ClientSettings { version: 1 },
        )
        .await
        .expect("typed upstream finishes discovery even for a deferred builder")
}

fn gateway(upstream: ExtensionStdioUpstream) -> ExtensionRegistration {
    gateway_with(builder(), upstream)
}

fn gateway_with(
    declaration: ExtensionBuilder<ClientSettings, ServerSettings, Settings>,
    upstream: ExtensionStdioUpstream,
) -> ExtensionRegistration {
    declaration
        .typed_stdio_proxy_request::<ScaleRequest, ScaleResponse>(
            METHOD,
            "scale-params-v1",
            "scale-result-v1",
            upstream,
        )
        .unwrap()
        .build()
        .unwrap()
}

async fn with_gateway<Exercise, ExerciseFuture>(
    cx: &Cx,
    registration: ExtensionRegistration,
    exercise: Exercise,
) where
    Exercise: FnOnce(MemoryTransport) -> ExerciseFuture,
    ExerciseFuture: Future<Output = ()>,
{
    with_gateway_owned(cx, registration, |peer, _server_cx| exercise(peer)).await;
}

async fn with_gateway_owned<Exercise, ExerciseFuture>(
    cx: &Cx,
    registration: ExtensionRegistration,
    exercise: Exercise,
) where
    Exercise: FnOnce(MemoryTransport, Cx) -> ExerciseFuture,
    ExerciseFuture: Future<Output = ()>,
{
    let server = modern::ServerBuilder::new("typed-stdio-gateway", "1")
        .extension(registration)
        .unwrap()
        .try_build()
        .unwrap();
    let (peer, transport) = create_memory_transport_pair_with_capacity(8);
    let (ready, mut readiness) = asupersync::channel::oneshot::channel();
    let mut serving = cx
        .spawn(move |server_cx| async move {
            ready.send(&server_cx, server_cx.clone()).unwrap();
            server.serve_memory(&server_cx, transport).await
        })
        .unwrap();
    let server_cx = readiness.recv(cx).await.unwrap();
    exercise(peer, server_cx).await;
    serving
        .join(cx)
        .await
        .expect("gateway scope settles")
        .expect("gateway closes");
}

#[test]
fn typed_stdio_proxy_preserves_contract_and_rebuilds_upstream_identity() {
    run(|cx| async move {
        let declaration_calls = Arc::new(AtomicUsize::new(0));
        let script = format!(
            r#"IFS= read -r discovery || exit 90
printf '%s\n' '{discovery}'
IFS= read -r first || exit 91
case "$first" in *'"id":2'*) ;; *) exit 92;; esac
case "$first" in *'"value":7'*) ;; *) exit 93;; esac
case "$first" in *'"name":"typed-stdio-proxy-upstream"'*) ;; *) exit 94;; esac
case "$first" in *'"com.example/typed-math":{{"version":1}}'*) ;; *) exit 95;; esac
case "$first" in *'downstream-only'*) exit 96;; esac
printf '%s\n' '{{"jsonrpc":"2.0","id":2,"result":{{"value":21,"_meta":{{"com.example/upstream-only":true}}}}}}'
IFS= read -r invalid_result || exit 97
case "$invalid_result" in *'"id":3'*) ;; *) exit 98;; esac
printf '%s\n' '{{"jsonrpc":"2.0","id":3,"result":{{"value":"wrong-type"}}}}'
IFS= read -r final || exit 99
case "$final" in *'"id":4'*) ;; *) exit 100;; esac
printf '%s\n' '{{"jsonrpc":"2.0","id":4,"result":{{"value":15}}}}'
while IFS= read -r ignored; do :; done
"#,
            discovery = discovery_response(3),
        );
        let upstream = connect_upstream(
            &cx,
            &script,
            registration(Arc::clone(&declaration_calls)),
        )
        .await;
        assert_eq!(upstream.descriptor().id(), EXTENSION);
        assert_eq!(declaration_calls.load(Ordering::SeqCst), 0);
        assert!(
            builder()
                .typed_stdio_proxy_request::<ScaleRequest, ScaleResponse>(
                    "tools/list",
                    "scale-params-v1",
                    "scale-result-v1",
                    upstream.clone(),
                )
                .is_err()
        );
        assert!(
            builder()
                .typed_stdio_proxy_request::<ScaleRequest, ScaleResponse>(
                    METHOD,
                    "different-params-v1",
                    "scale-result-v1",
                    upstream.clone(),
                )
                .unwrap()
                .build()
                .is_err(),
            "equal JSON shapes cannot replace an exact schema identity"
        );
        assert!(
            builder()
                .typed_stdio_proxy_request::<ScaleRequest, ScaleResponse>(
                    METHOD,
                    "scale-params-v1",
                    "scale-result-v1",
                    upstream.clone(),
                )
                .unwrap()
                .typed_request_notification::<ScaleResponse>(
                    EVENT,
                    "request-scaled-v1",
                    OWNER,
                )
                .unwrap()
                .build()
                .is_err(),
            "a later declaration cannot silently widen a request-only proxy"
        );
        let request_cx = cx.clone();
        with_gateway(&cx, gateway(upstream.clone()), move |mut peer| async move {
            peer.send_async(
                &request_cx,
                &request(40, Some(json!({"version": 1})), json!("bad-input")),
            )
            .await
            .unwrap();
            assert!(response(&request_cx, &mut peer, 40).await.error.is_some());

            let mut first = request(41, Some(json!({"version": 1})), json!(7));
            let JsonRpcMessage::Request(first_request) = &mut first else {
                unreachable!()
            };
            first_request.params.as_mut().unwrap()["_meta"]["com.example/downstream-only"] =
                json!("must-not-cross");
            peer.send_async(&request_cx, &first).await.unwrap();
            let first = response(&request_cx, &mut peer, 41).await;
            assert!(first.error.is_none(), "{first:?}");
            assert_eq!(first.result.unwrap(), json!({"value": 21}));

            peer.send_async(
                &request_cx,
                &request(42, Some(json!({"version": 1})), json!(13)),
            )
            .await
            .unwrap();
            assert!(response(&request_cx, &mut peer, 42).await.error.is_some());
            peer.send_async(
                &request_cx,
                &request(43, Some(json!({"version": 1})), json!(5)),
            )
            .await
            .unwrap();
            let final_result = response(&request_cx, &mut peer, 43).await;
            assert!(final_result.error.is_none(), "{final_result:?}");
            assert_eq!(final_result.result.unwrap(), json!({"value": 15}));
        })
        .await;
        assert_eq!(declaration_calls.load(Ordering::SeqCst), 0);
        upstream.close_with_cx(&cx).await.unwrap();
    });
}

fn builder_with_multiplier(
    multiplier: u32,
) -> ExtensionBuilder<ClientSettings, ServerSettings, Settings> {
    ExtensionBuilder::new(
        EXTENSION,
        1,
        "typed-math-client-v1",
        "typed-math-server-v1",
        ServerSettings { version: 1, multiplier },
        |client: ClientSettings, server: ServerSettings| {
            if client.version != server.version {
                return Err(McpError::invalid_params("incompatible math version"));
            }
            Ok(Settings { multiplier: server.multiplier })
        },
    )
    .unwrap()
}

#[test]
fn typed_stdio_proxy_refuses_settings_mismatch_before_consuming_upstream_id() {
    run(|cx| async move {
        let script = format!(
            r#"IFS= read -r discovery || exit 90
printf '%s\n' '{discovery}'
IFS= read -r first || exit 91
case "$first" in *'"id":2'*) ;; *) exit 92;; esac
case "$first" in *'"value":5'*) ;; *) exit 93;; esac
printf '%s\n' '{{"jsonrpc":"2.0","id":2,"result":{{"value":45}}}}'
while IFS= read -r ignored; do :; done
"#,
            discovery = discovery_response(9),
        );
        let upstream =
            connect_upstream(&cx, &script, registration(Arc::new(AtomicUsize::new(0)))).await;
        let request_cx = cx.clone();
        with_gateway(&cx, gateway(upstream.clone()), move |mut peer| async move {
            peer.send_async(
                &request_cx,
                &request(41, Some(json!({"version": 1})), json!(7)),
            )
            .await
            .unwrap();
            assert!(response(&request_cx, &mut peer, 41).await.error.is_some());
        })
        .await;
        let request_cx = cx.clone();
        with_gateway(
            &cx,
            gateway_with(builder_with_multiplier(9), upstream.clone()),
            move |mut peer| async move {
                peer.send_async(
                    &request_cx,
                    &request(42, Some(json!({"version": 1})), json!(5)),
                )
                .await
                .unwrap();
                let result = response(&request_cx, &mut peer, 42).await;
                assert!(result.error.is_none(), "{result:?}");
                assert_eq!(result.result.unwrap(), json!({"value": 45}));
            },
        )
        .await;
        upstream.close_with_cx(&cx).await.unwrap();
    });
}

fn notification_producer() -> ExtensionRegistration {
    builder()
        .typed_request_notification::<ScaleResponse>(EVENT, "request-scaled-v1", OWNER)
        .unwrap()
        .typed_request_sync(
            METHOD,
            "scale-params-v1",
            "scale-result-v1",
            |_context: ExtensionContext<'_, Settings>, _request: ScaleRequest| -> McpResult<ScaleResponse> {
                panic!("upstream declaration handlers must never execute")
            },
        )
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn typed_stdio_proxy_multiplexes_requests_and_recorrelates_owned_notifications() {
    run(|cx| async move {
        let script = format!(
            r#"IFS= read -r discovery || exit 90
printf '%s\n' '{discovery}'
IFS= read -r first || exit 91
IFS= read -r second || exit 92
case "$first" in *'"id":2'*) ;; *) exit 93;; esac
case "$second" in *'"id":3'*) ;; *) exit 94;; esac
case "$first" in *'"value":7'*) first_value=21;; *'"value":9'*) first_value=27;; *) exit 95;; esac
case "$second" in *'"value":7'*) second_value=21;; *'"value":9'*) second_value=27;; *) exit 96;; esac
printf '{{"jsonrpc":"2.0","method":"com.example/request-scaled","params":{{"value":%s,"_meta":{{"com.example/request-id":3,"com.example/upstream-only":true}}}}}}\n' "$second_value"
printf '{{"jsonrpc":"2.0","id":3,"result":{{"value":%s}}}}\n' "$second_value"
printf '{{"jsonrpc":"2.0","method":"com.example/request-scaled","params":{{"value":%s,"_meta":{{"com.example/request-id":2,"com.example/upstream-only":true}}}}}}\n' "$first_value"
printf '{{"jsonrpc":"2.0","id":2,"result":{{"value":%s}}}}\n' "$first_value"
while IFS= read -r ignored; do :; done
"#,
            discovery = discovery_response(3),
        );
        let upstream = connect_upstream(&cx, &script, notification_producer()).await;
        assert!(
            builder()
                .typed_stdio_proxy_request::<ScaleRequest, ScaleResponse>(
                    METHOD, "scale-params-v1", "scale-result-v1", upstream.clone(),
                )
                .is_err(),
            "request-owned events require the explicit notification route"
        );
        let registration = builder()
            .typed_request_notification::<ScaleResponse>(EVENT, "request-scaled-v1", OWNER)
            .unwrap()
            .typed_stdio_proxy_request_with_notifications::<
                ScaleRequest, ScaleResponse, ScaleResponse,
            >(
                METHOD, "scale-params-v1", "scale-result-v1", upstream.clone(),
            )
            .unwrap()
            .build()
            .unwrap();
        let request_cx = cx.clone();
        with_gateway(&cx, registration, move |mut peer| async move {
            for (id, value) in [(41, 7), (42, 9)] {
                peer.send_async(
                    &request_cx,
                    &request(id, Some(json!({"version": 1})), json!(value)),
                )
                .await
                .unwrap();
            }
            let mut events = BTreeMap::new();
            let mut results = BTreeMap::new();
            for _ in 0..4 {
                match peer.recv_async(&request_cx).await.unwrap() {
                    JsonRpcMessage::Request(notification) => {
                        assert!(notification.id.is_none());
                        assert_eq!(notification.method, EVENT);
                        let parameters = notification.params.unwrap();
                        let owner = parameters["_meta"][OWNER].as_i64().unwrap();
                        let expected = match owner {
                            41 => 21,
                            42 => 27,
                            _ => panic!("upstream correlation escaped to downstream"),
                        };
                        assert_eq!(parameters["value"], expected);
                        assert_eq!(parameters["_meta"], json!({OWNER: owner}));
                        assert!(events.insert(owner, expected).is_none());
                    }
                    JsonRpcMessage::Response(response) => {
                        assert!(response.error.is_none(), "{response:?}");
                        let Some(RequestId::Number(owner)) = response.id else {
                            panic!("downstream numeric request owner is preserved");
                        };
                        let value = response.result.unwrap()["value"].as_i64().unwrap();
                        assert_eq!(events.get(&owner), Some(&value));
                        assert!(results.insert(owner, value).is_none());
                    }
                }
            }
            assert_eq!(results, BTreeMap::from([(41, 21), (42, 27)]));
        })
        .await;
        upstream.close_with_cx(&cx).await.unwrap();
    });
}

static NEXT_MARKER: AtomicUsize = AtomicUsize::new(0);

struct Marker(PathBuf);

impl Marker {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fastmcp-typed-stdio-gateway-{}-{}",
            std::process::id(),
            NEXT_MARKER.fetch_add(1, Ordering::SeqCst),
        ));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        Self(path)
    }
}

impl Drop for Marker {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn wait_for_marker(cx: &Cx, path: &Path, event: &str) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(3), async {
        loop {
            let observations = std::fs::read_to_string(path).unwrap();
            if observations.lines().any(|line| line == event) {
                return;
            }
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the idle child observes retirement without another upstream request");
}

fn interruption(cancel_explicitly: bool) {
    run(|cx| async move {
        let marker = Marker::new();
        let script = format!(
            r#"IFS= read -r discovery || exit 90
printf '%s\n' '{discovery}'
IFS= read -r first || exit 91
case "$first" in *'"id":2'*) ;; *) exit 92;; esac
printf '%s\n' request >> "$1"
IFS= read -r control || exit 93
case "$control" in *'"method":"notifications/cancelled"'*) ;; *) exit 94;; esac
case "$control" in *'"requestId":2'*) ;; *) exit 95;; esac
printf '%s\n' cancel >> "$1"
IFS= read -r followup || exit 96
case "$followup" in *'"id":3'*) ;; *) exit 97;; esac
printf '%s\n' '{{"jsonrpc":"2.0","id":3,"result":{{"value":15}}}}'
while IFS= read -r ignored; do :; done
"#,
            discovery = discovery_response(3),
        );
        let upstream = modern::ClientBuilder::new()
            .connect_extension_stdio_upstream_with_cx(
                &cx,
                "sh",
                &["-c", &script, "typed-stdio-retirement", marker.0.to_str().unwrap()],
                registration(Arc::new(AtomicUsize::new(0))),
                &ClientSettings { version: 1 },
            )
            .await
            .unwrap();
        let request_cx = cx.clone();
        let observations = marker.0.clone();
        with_gateway_owned(&cx, gateway(upstream.clone()), move |mut peer, server_cx| async move {
            peer.send_async(
                &request_cx,
                &request(41, Some(json!({"version": 1})), json!(7)),
            )
            .await
            .unwrap();
            wait_for_marker(&request_cx, &observations, "request").await;
            if cancel_explicitly {
                peer.send_async(
                    &request_cx,
                    &JsonRpcMessage::Request(JsonRpcRequest::notification(
                        "notifications/cancelled",
                        Some(json!({"requestId": 41})),
                    )),
                )
                .await
                .unwrap();
                wait_for_marker(&request_cx, &observations, "cancel").await;
            } else {
                server_cx.cancel_with(
                    asupersync::types::CancelKind::Shutdown,
                    Some("drop the downstream request scope"),
                );
                drop(peer);
                wait_for_marker(&request_cx, &observations, "cancel").await;
            }
        })
        .await;

        let request_cx = cx.clone();
        with_gateway(&cx, gateway(upstream.clone()), move |mut peer| async move {
            peer.send_async(
                &request_cx,
                &request(42, Some(json!({"version": 1})), json!(5)),
            )
            .await
            .unwrap();
            let result = response(&request_cx, &mut peer, 42).await;
            assert!(result.error.is_none(), "{result:?}");
            assert_eq!(result.result.unwrap(), json!({"value": 15}));
        })
        .await;
        upstream.close_with_cx(&cx).await.unwrap();
    });
}

#[test]
fn typed_stdio_proxy_cancellation_retires_idle_child_and_preserves_shared_connection() {
    interruption(true);
}

#[test]
fn typed_stdio_proxy_scope_cancellation_retires_idle_child_and_preserves_shared_connection() {
    interruption(false);
}

fn relaxed_builder() -> ExtensionBuilder<ClientSettings, ServerSettings, Settings> {
    ExtensionBuilder::new(
        EXTENSION,
        1,
        "typed-math-client-v1",
        "typed-math-server-v1",
        ServerSettings { version: 1, multiplier: 3 },
        |_client: ClientSettings, server: ServerSettings| {
            Ok(Settings { multiplier: server.multiplier })
        },
    )
    .unwrap()
}

fn client_notification_declaration() -> ExtensionRegistration {
    relaxed_builder()
        .typed_request_sync(
            METHOD,
            "scale-params-v1",
            "scale-result-v1",
            |_context: ExtensionContext<'_, Settings>, request: ScaleRequest| {
                Ok(ScaleResponse { value: request.value * 3 })
            },
        )
        .unwrap()
        .typed_notification_sync::<ScaleNotification, _, _>(
            NOTIFICATION,
            "scaled-notification-v1",
            ACTIVATION,
            |_| Ok(()),
            |_context, _notification| {
                panic!("upstream declaration notification must never run");
            },
        )
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn typed_stdio_proxy_client_notifications_rebuild_proof_without_allocating_ids() {
    run(|cx| async move {
        let script = format!(
            r#"IFS= read -r discovery || exit 90
printf '%s\n' '{discovery}'
count=0
while [ "$count" -lt 2 ]; do
    IFS= read -r frame || exit 91
    case "$frame" in
        *'"method":"{notification}"'*)
            case "$frame" in *'"value":11'*) ;; *) exit 92;; esac
            case "$frame" in *'"{activation}":{{"version":1}}'*) ;; *) exit 93;; esac
            case "$frame" in *'"id":'*) exit 94;; esac
            case "$frame" in *'downstream-only'*|*'io.modelcontextprotocol/clientInfo'*) exit 95;; esac
            ;;
        *'"method":"{method}"'*)
            case "$frame" in *'"id":2'*) ;; *) exit 96;; esac
            case "$frame" in *'"value":7'*) ;; *) exit 97;; esac
            ;;
        *) exit 98;;
    esac
    count=$((count + 1))
done
printf '%s\n' '{{"jsonrpc":"2.0","id":2,"result":{{"value":21}}}}'
while IFS= read -r ignored; do :; done
"#,
            discovery = discovery_response(3),
            notification = NOTIFICATION,
            activation = ACTIVATION,
            method = METHOD,
        );
        let upstream = connect_upstream(&cx, &script, client_notification_declaration()).await;
        let authorized = Arc::new(AtomicUsize::new(0));
        let policy_calls = Arc::clone(&authorized);
        let registration = relaxed_builder()
            .typed_stdio_proxy_request::<ScaleRequest, ScaleResponse>(
                METHOD, "scale-params-v1", "scale-result-v1", upstream.clone(),
            )
            .unwrap()
            .typed_stdio_proxy_notification(
                NOTIFICATION,
                "scaled-notification-v1",
                ACTIVATION,
                move |notification: &ScaleNotification| {
                    policy_calls.fetch_add(1, Ordering::SeqCst);
                    if notification.value == 13 {
                        return Err(McpError::invalid_params("operation denied"));
                    }
                    Ok(())
                },
                upstream.clone(),
            )
            .unwrap()
            .build()
            .unwrap();
        let request_cx = cx.clone();
        with_gateway(&cx, registration, move |mut peer| async move {
            for value in [json!("wrong-type"), json!(13), json!(11)] {
                peer.send_async(
                    &request_cx,
                    &JsonRpcMessage::Request(JsonRpcRequest::notification(
                        NOTIFICATION,
                        Some(json!({
                            "value": value,
                            "hold": false,
                            "_meta": {
                                (ACTIVATION): {"version": 2},
                                "com.example/downstream-only": "must-not-cross"
                            }
                        })),
                    )),
                )
                .await
                .unwrap();
            }
            peer.send_async(
                &request_cx,
                &request(41, Some(json!({"version": 2})), json!(7)),
            )
            .await
            .unwrap();
            let result = response(&request_cx, &mut peer, 41).await;
            assert!(result.error.is_none(), "{result:?}");
            assert_eq!(result.result.unwrap(), json!({"value": 21}));
        })
        .await;
        assert_eq!(authorized.load(Ordering::SeqCst), 2);
        upstream.close_with_cx(&cx).await.unwrap();
    });
}
