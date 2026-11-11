//! Typed gateway routes use two real HTTP legs and ordinary scoped shutdown.

use std::future::Future;
use std::sync::Mutex;
use std::task::Poll;

use super::*;
use fastmcp_rust::client::http_executor::{
    ModernHttpExtensionEvent, ModernHttpExtensionExecution,
};
use fastmcp_rust::extensions::authoring::ExtensionHttpUpstream;
use fastmcp_rust::{McpContext, Middleware, MiddlewareDecision};

async fn with_http_server<Exercise, ExerciseFuture>(
    cx: &Cx,
    server: modern::ServerBuilder,
    exercise: Exercise,
) where
    Exercise: FnOnce(CanonicalHttpUrl) -> ExerciseFuture,
    ExerciseFuture: Future<Output = ()>,
{
    let server = server.try_build().unwrap();
    let bound = server.bind_http(cx, "127.0.0.1:0").await.unwrap();
    let endpoint =
        CanonicalHttpUrl::parse(&format!("http://{}/mcp", bound.local_addr().unwrap())).unwrap();
    let (ready, mut receiver) = asupersync::channel::oneshot::channel();
    let mut serving = cx
        .spawn(move |server_cx| async move {
            ready.send(&server_cx, server_cx.clone()).unwrap();
            bound.serve(&server_cx).await
        })
        .unwrap();
    let server_cx = receiver.recv(cx).await.unwrap();
    exercise(endpoint).await;
    server_cx.cancel_with(
        asupersync::types::CancelKind::Shutdown,
        Some("typed HTTP proxy fixture complete"),
    );
    assert!(matches!(
        serving.join(cx).await.unwrap().unwrap(),
        fastmcp_rust::HttpServerShutdown::Quiescent
    ));
}

fn run_http_test<Exercise, ExerciseFuture>(server: modern::ServerBuilder, exercise: Exercise)
where
    Exercise: FnOnce(Cx, CanonicalHttpUrl) -> ExerciseFuture,
    ExerciseFuture: Future<Output = ()>,
{
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(
            cx.now(),
            Duration::from_secs(15),
            with_http_server(&cx, server, |endpoint| exercise(cx.clone(), endpoint)),
        )
        .await
        .expect("bounded real HTTP proxy exchange and shutdown");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

async fn connect_upstream(
    cx: &Cx,
    endpoint: CanonicalHttpUrl,
    declaration: ExtensionRegistration,
) -> ExtensionHttpUpstream {
    modern::ClientBuilder::new()
        .client_info("typed-proxy-upstream", "1.0")
        .connect_extension_http_upstream_with_cx(
            cx,
            endpoint,
            declaration,
            &ClientSettings { version: 1 },
        )
        .await
        .unwrap()
}

async fn connect_downstream(cx: &Cx, endpoint: CanonicalHttpUrl) -> modern::HttpClient {
    let (_, descriptors, discovery) = client_configuration();
    modern::ClientBuilder::new()
        .client_info("typed-proxy-downstream", "1.0")
        .extension_registry(descriptors, discovery, || accept_settings)
        .unwrap()
        .connect_http_with_cx(cx, endpoint)
        .await
        .unwrap()
}

fn gateway(upstream: ExtensionHttpUpstream) -> modern::ServerBuilder {
    let registration = builder()
        .typed_http_proxy_request::<ScaleRequest, ScaleResponse>(
            METHOD,
            "scale-params-v1",
            "scale-result-v1",
            upstream,
        )
        .unwrap()
        .build()
        .unwrap();
    modern::ServerBuilder::new("typed-proxy-gateway", "1.0")
        .extension(registration)
        .unwrap()
}

fn limits() -> fastmcp_rust::client::sse::SseLimits {
    fastmcp_rust::client::sse::SseLimits::with_data_lines(
        fastmcp_rust::core::DEFAULT_JSON_RPC_MAX_BODY_BYTES + b"data: \r\n".len(),
        fastmcp_rust::client::http_executor::MAX_PENDING_MODERN_HTTP_SSE_EVENT_BYTES,
        64,
        4096,
    )
    .unwrap()
}

async fn terminal(cx: &Cx, execution: &mut ModernHttpExtensionExecution) -> serde_json::Value {
    let Some(ModernHttpExtensionEvent::Terminal(result)) =
        execution.next_event(cx).await.expect("typed terminal result")
    else {
        panic!("fixture has one terminal result and no intermediate events");
    };
    result
}

#[derive(Clone)]
struct UpstreamProbe(Arc<Mutex<Vec<JsonRpcRequest>>>);

impl Middleware for UpstreamProbe {
    fn on_request(
        &self,
        _context: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        if request.method == METHOD {
            self.0.lock().unwrap().push(request.clone());
        }
        Ok(MiddlewareDecision::Continue)
    }

    fn on_response(
        &self,
        _context: &McpContext,
        request: &JsonRpcRequest,
        mut response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        if request.method == METHOD {
            if request.params.as_ref().and_then(|params| params.get("value")) == Some(&json!(13)) {
                // A normal server middleware can expose a bad peer result after
                // its typed handler. The gateway must independently validate it.
                return Ok(json!({"value": "not-an-integer"}));
            }
            response["_meta"] = json!({"com.example/upstream-only": "do-not-forward"});
        }
        Ok(response)
    }
}

#[test]
fn typed_http_proxy_validates_both_legs_and_rebuilds_identity() {
    let calls = Arc::new(AtomicUsize::new(0));
    let declaration_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let server = modern::ServerBuilder::new("typed-proxy-producer", "1.0")
        .extension(registration(Arc::clone(&calls)))
        .unwrap()
        .middleware(UpstreamProbe(Arc::clone(&observed)));
    let retained_calls = Arc::clone(&calls);
    let retained_declaration = Arc::clone(&declaration_calls);
    run_http_test(server, move |cx, endpoint| async move {
        let upstream = connect_upstream(&cx, endpoint, registration(declaration_calls)).await;
        assert_eq!(upstream.descriptor().id(), EXTENSION);

        assert!(
            builder()
                .typed_http_proxy_request::<ScaleRequest, ScaleResponse>(
                    "tools/list", "scale-params-v1", "scale-result-v1", upstream.clone(),
                )
                .is_err(),
            "an extension route cannot borrow a core method"
        );
        assert!(
            builder()
                .typed_http_proxy_request::<ScaleRequest, ScaleResponse>(
                    METHOD, "different-params-v1", "scale-result-v1", upstream.clone(),
                )
                .unwrap()
                .build()
                .is_err(),
            "matching JSON shapes cannot replace an exact schema identity"
        );
        assert!(
            builder()
                .typed_http_proxy_request::<ScaleRequest, ScaleResponse>(
                    METHOD, "scale-params-v1", "scale-result-v1", upstream.clone(),
                )
                .unwrap()
                .typed_request_notification::<ScaleResponse>(
                    "com.example/changed", "changed-v1", "com.example/request-id",
                )
                .unwrap()
                .build()
                .is_err(),
            "a later notification declaration cannot bypass the request-only route"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        with_http_server(&cx, gateway(upstream), |endpoint| async {
            let mut client = connect_downstream(&cx, endpoint).await;
            let id = ExtensionId::parse(EXTENSION).unwrap();
            client
                .request_final_extension(&cx, &id, METHOD, json!({"value": "bad-input"}))
                .await
                .expect_err("downstream parameter validation precedes upstream effects");
            assert_eq!(calls.load(Ordering::SeqCst), 0);

            let mut valid = client
                .execute_final_extension(
                    &cx,
                    &id,
                    METHOD,
                    json!({"value": 7, "_meta": {
                        "com.example/caller-only": "do-not-forward",
                        "io.modelcontextprotocol/clientInfo": {
                            "name": "spoofed-downstream", "version": "0"
                        }
                    }}),
                    limits(),
                )
                .unwrap();
            let downstream_id = valid.request_id().clone();
            assert_eq!(terminal(&cx, &mut valid).await, json!({"value": 21}));
            drop(valid);

            client
                .request_final_extension(&cx, &id, METHOD, json!({"value": 13}))
                .await
                .expect_err("a malformed upstream typed result cannot reach the downstream client");
            assert_eq!(
                client.request_final_extension(&cx, &id, METHOD, json!({"value": 11}))
                    .await.unwrap(),
                json!({"value": 33}),
                "a rejected peer result does not poison the shared upstream"
            );
            let requests = observed.lock().unwrap();
            assert_eq!(requests.len(), 3);
            assert_ne!(
                requests[0].id.as_ref(), Some(&downstream_id),
                "the independently allocated upstream ID does not reuse downstream custody"
            );
            assert_ne!(requests[0].id, requests[1].id);
            for request in requests.iter() {
                let meta = &request.params.as_ref().unwrap()["_meta"];
                assert_eq!(
                    meta["io.modelcontextprotocol/clientInfo"]["name"],
                    "typed-proxy-upstream"
                );
                assert!(meta.get("com.example/caller-only").is_none());
                assert_eq!(
                    meta["io.modelcontextprotocol/clientCapabilities"]["extensions"][EXTENSION],
                    json!({"version": 1})
                );
            }
        })
        .await;
    });
    assert_eq!(retained_calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        retained_declaration.load(Ordering::SeqCst), 0,
        "connecting a declaration never invokes its application callbacks"
    );
}

#[test]
fn typed_http_proxy_refuses_effective_settings_mismatch_before_upstream_dispatch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let retained = Arc::clone(&calls);
    let server = modern::ServerBuilder::new("typed-settings-producer", "1.0")
        .extension(registration(Arc::clone(&calls)))
        .unwrap();
    run_http_test(server, move |cx, endpoint| async move {
        let upstream = connect_upstream(
            &cx, endpoint, registration(Arc::new(AtomicUsize::new(0))),
        ).await;
        let changed = ExtensionBuilder::new(
            EXTENSION,
            1,
            "typed-math-client-v1",
            "typed-math-server-v1",
            ServerSettings { version: 1, multiplier: 5 },
            |client: ClientSettings, server: ServerSettings| {
                if client.version != server.version {
                    return Err(McpError::invalid_params("incompatible math version"));
                }
                Ok(Settings { multiplier: server.multiplier })
            },
        )
        .unwrap()
        .typed_http_proxy_request::<ScaleRequest, ScaleResponse>(
            METHOD, "scale-params-v1", "scale-result-v1", upstream.clone(),
        )
        .unwrap()
        .build()
        .expect("settings values are negotiated independently of the compiled schema contract");
        let changed = modern::ServerBuilder::new("typed-settings-gateway", "1.0")
            .extension(changed).unwrap();
        with_http_server(&cx, changed, |endpoint| async {
            let mut client = connect_downstream(&cx, endpoint).await;
            client.request_final_extension(
                &cx, &ExtensionId::parse(EXTENSION).unwrap(), METHOD, json!({"value": 7}),
            ).await.expect_err("3 and 5 are individually valid but not interchangeable settings");
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }).await;
        with_http_server(&cx, gateway(upstream), |endpoint| async {
            let mut client = connect_downstream(&cx, endpoint).await;
            assert_eq!(
                client.request_final_extension(
                    &cx, &ExtensionId::parse(EXTENSION).unwrap(), METHOD, json!({"value": 7}),
                ).await.unwrap(),
                json!({"value": 21})
            );
        }).await;
    });
    assert_eq!(retained.load(Ordering::SeqCst), 1);
}

#[test]
fn typed_http_proxy_cancel_retires_only_the_owned_upstream_request() {
    interrupted_request_keeps_siblings(false);
}

#[test]
fn typed_http_proxy_drop_retires_only_the_owned_upstream_request() {
    interrupted_request_keeps_siblings(true);
}

fn interrupted_request_keeps_siblings(drop_request: bool) {
    let observations = Arc::new(NotificationObservations::default());
    let retained = Arc::clone(&observations);
    let registration = builder()
        .typed_request(
            METHOD, "scale-params-v1", "scale-result-v1",
            CancellableScaleHandler(Arc::clone(&observations)),
        )
        .unwrap().build().unwrap();
    let server = modern::ServerBuilder::new("typed-cancellable-producer", "1.0")
        .extension(registration).unwrap();
    run_http_test(server, move |cx, endpoint| async move {
        let upstream = connect_upstream(
            &cx, endpoint, super::registration(Arc::new(AtomicUsize::new(0))),
        ).await;
        with_http_server(&cx, gateway(upstream), |endpoint| async {
            let client = connect_downstream(&cx, endpoint).await;
            let id = ExtensionId::parse(EXTENSION).unwrap();
            let mut held = client.execute_final_extension(
                &cx, &id, METHOD, json!({"value": 7}), limits(),
            ).unwrap();
            let control = held.control();
            {
                let mut receiving = Box::pin(held.next_event(&cx));
                while observations.started.load(Ordering::SeqCst) == 0 {
                    assert!(
                        std::future::poll_fn(|task| Poll::Ready(receiving.as_mut().poll(task)))
                            .await.is_pending(),
                        "the first upstream handler starts and remains parked"
                    );
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                }
            }
            let mut sibling = client.execute_final_extension(
                &cx, &id, METHOD, json!({"value": 11}), limits(),
            ).unwrap();
            assert_eq!(terminal(&cx, &mut sibling).await, json!({"value": 33}));
            drop(sibling);
            assert_eq!(observations.abandoned.load(Ordering::SeqCst), 0);
            if drop_request {
                drop(held);
            } else {
                assert!(control.cancel());
                held.next_event(&cx).await.expect_err("owned cancellation is terminal");
                drop(held);
            }
            asupersync::time::timeout(cx.now(), Duration::from_secs(2), async {
                while observations.abandoned.load(Ordering::SeqCst) == 0 {
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                }
            }).await.expect("both HTTP legs release the abandoned handler before listener shutdown");
            assert!(cx.checkpoint().is_ok());
            let mut following = client.execute_final_extension(
                &cx, &id, METHOD, json!({"value": 17}), limits(),
            ).unwrap();
            assert_eq!(terminal(&cx, &mut following).await, json!({"value": 51}));
            drop(following);
        }).await;
    });
    assert_eq!(retained.started.load(Ordering::SeqCst), 3);
    assert_eq!(retained.completed.load(Ordering::SeqCst), 2);
    assert_eq!(retained.abandoned.load(Ordering::SeqCst), 1);
}

#[derive(Deserialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ForgedRequest {
    value: u32,
}

impl Serialize for ForgedRequest {
    fn serialize<S: fastmcp_rust::serde::Serializer>(
        &self, serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use fastmcp_rust::serde::ser::SerializeMap;
        let mut object = serializer.serialize_map(Some(2))?;
        object.serialize_entry("value", &self.value)?;
        object.serialize_entry("_meta", &json!({"com.example/forged": true}))?;
        object.end()
    }
}

fn forged_registration(calls: Arc<AtomicUsize>) -> ExtensionRegistration {
    builder()
        .typed_request_sync(
            METHOD, "forged-params-v1", "scale-result-v1",
            move |_context: ExtensionContext<'_, Settings>, request: ForgedRequest| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(ScaleResponse { value: request.value })
            },
        )
        .unwrap().build().unwrap()
}

#[test]
fn typed_http_proxy_rejects_metadata_synthesized_by_typed_request_serialization() {
    let calls = Arc::new(AtomicUsize::new(0));
    let retained = Arc::clone(&calls);
    let server = modern::ServerBuilder::new("typed-forged-producer", "1.0")
        .extension(forged_registration(calls)).unwrap();
    run_http_test(server, move |cx, endpoint| async move {
        let upstream = connect_upstream(
            &cx, endpoint, forged_registration(Arc::new(AtomicUsize::new(0))),
        ).await;
        let registration = builder()
            .typed_http_proxy_request::<ForgedRequest, ScaleResponse>(
                METHOD, "forged-params-v1", "scale-result-v1", upstream,
            )
            .unwrap().build().unwrap();
        let gateway = modern::ServerBuilder::new("typed-forged-gateway", "1.0")
            .extension(registration).unwrap();
        with_http_server(&cx, gateway, |endpoint| async {
            let mut client = connect_downstream(&cx, endpoint).await;
            client.request_final_extension(
                &cx, &ExtensionId::parse(EXTENSION).unwrap(), METHOD, json!({"value": 7}),
            ).await.expect_err("custom serialization cannot recreate stripped protocol authority");
        }).await;
    });
    assert_eq!(retained.load(Ordering::SeqCst), 0);
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct Echo {
    text: String,
}

fn echo_registration() -> ExtensionRegistration {
    builder()
        .typed_request_sync(
            METHOD, "echo-params-v1", "echo-result-v1",
            |_context: ExtensionContext<'_, Settings>, request: Echo| Ok(request),
        )
        .unwrap().build().unwrap()
}

#[test]
fn typed_http_proxy_preserves_large_typed_results() {
    let server = modern::ServerBuilder::new("typed-large-producer", "1.0")
        .extension(echo_registration()).unwrap();
    run_http_test(server, |cx, endpoint| async move {
        let upstream = connect_upstream(&cx, endpoint, echo_registration()).await;
        let registration = builder()
            .typed_http_proxy_request::<Echo, Echo>(
                METHOD, "echo-params-v1", "echo-result-v1", upstream,
            )
            .unwrap().build().unwrap();
        let gateway = modern::ServerBuilder::new("typed-large-gateway", "1.0")
            .extension(registration).unwrap();
        with_http_server(&cx, gateway, |endpoint| async {
            let mut client = connect_downstream(&cx, endpoint).await;
            let text = "x".repeat(128 * 1024);
            let result = client.request_final_extension(
                &cx, &ExtensionId::parse(EXTENSION).unwrap(), METHOD,
                json!({"text": text}),
            ).await.unwrap();
            assert_eq!(result["text"].as_str().unwrap().len(), 128 * 1024);
            assert!(result["text"].as_str().unwrap().bytes().all(|byte| byte == b'x'));
        }).await;
    });
}

#[test]
fn typed_http_proxy_connection_requires_upstream_activation_and_request_only_contract() {
    let server = modern::ServerBuilder::new("no-authored-extension", "1.0");
    run_http_test(server, |cx, endpoint| async move {
        modern::ClientBuilder::new()
            .connect_extension_http_upstream_with_cx(
                &cx, endpoint.clone(), registration(Arc::new(AtomicUsize::new(0))),
                &ClientSettings { version: 1 },
            ).await.expect_err("remote discovery must independently activate the extension");
        let observations = Arc::new(NotificationObservations::default());
        modern::ClientBuilder::new()
            .connect_extension_http_upstream_with_cx(
                &cx, endpoint,
                duplex_registration(Arc::new(AtomicUsize::new(0)), observations),
                &ClientSettings { version: 1 },
            ).await.expect_err("notification declarations are excluded before connecting");
    });
}
