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
        let calls = Arc::new(AtomicUsize::new(0));
        let error = modern::ClientBuilder::new()
            .connect_extension_http_upstream_with_cx(
                &cx, endpoint,
                duplex_registration(Arc::clone(&calls), Arc::clone(&observations)),
                &ClientSettings { version: 1 },
            )
            .await
            .expect_err("standalone client notification declarations are excluded before connecting");
        assert_eq!(error.code, fastmcp_rust::McpErrorCode::InvalidParams);
        assert!(error.message.contains("client notification declarations"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(observations.authorized.load(Ordering::SeqCst), 0);
        assert_eq!(observations.started.load(Ordering::SeqCst), 0);
    });
}

const PROXY_NOTICE: &str = "com.example/proxy-scaled";
const PROXY_NOTICE_OWNER: &str = "com.example/proxy-owner";

struct ProxyNoticeProducer {
    observations: Arc<NotificationObservations>,
    malformed: bool,
}

impl fastmcp_rust::extensions::authoring::ExtensionHandler<ScaleRequest, ScaleResponse, Settings>
    for ProxyNoticeProducer
{
    fn handle<'a>(
        &'a self,
        context: ExtensionContext<'a, Settings>,
        request: ScaleRequest,
    ) -> fastmcp_rust::BoxFuture<'a, McpResult<ScaleResponse>> {
        Box::pin(async move {
            let mut guard = NotificationGuard {
                observations: Arc::clone(&self.observations),
                completed: false,
            };
            self.observations.started.fetch_add(1, Ordering::SeqCst);
            if self.malformed && request.value == 13 {
                context.notify(&json!({"value": "wrong-notification-type"}))?;
            } else {
                context.notify(&ScaleResponse {
                    value: request.value * context.settings().multiplier,
                })?;
            }
            if request.value == 7 {
                std::future::pending::<()>().await;
            }
            context.checkpoint()?;
            self.observations.completed.fetch_add(1, Ordering::SeqCst);
            guard.completed = true;
            Ok(ScaleResponse {
                value: request.value * context.settings().multiplier,
            })
        })
    }
}

fn notice_producer<Notice: Serialize + fastmcp_rust::schema::JsonSchemaType>(
    observations: Arc<NotificationObservations>,
    malformed: bool,
) -> ExtensionRegistration {
    builder()
        .typed_request_notification::<Notice>(
            PROXY_NOTICE,
            "proxy-notice-v1",
            PROXY_NOTICE_OWNER,
        )
        .unwrap()
        .typed_request(
            METHOD,
            "scale-params-v1",
            "scale-result-v1",
            ProxyNoticeProducer { observations, malformed },
        )
        .unwrap()
        .build()
        .unwrap()
}

fn notice_gateway<Notice>(upstream: ExtensionHttpUpstream) -> ExtensionRegistration
where
    Notice: fastmcp_rust::serde::de::DeserializeOwned
        + Serialize
        + fastmcp_rust::schema::JsonSchemaType
        + Send
        + 'static,
{
    builder()
        .typed_request_notification::<Notice>(
            PROXY_NOTICE,
            "proxy-notice-v1",
            PROXY_NOTICE_OWNER,
        )
        .unwrap()
        .typed_http_proxy_request_with_notifications::<ScaleRequest, ScaleResponse, Notice>(
            METHOD,
            "scale-params-v1",
            "scale-result-v1",
            upstream,
        )
        .unwrap()
        .build()
        .unwrap()
}

fn notice_client_configuration() -> (
    ExtensionId,
    ExtensionDescriptorRegistry,
    ClientExtensionDiscovery,
) {
    let (id, original, mut discovery) = client_configuration();
    let mut descriptor = original.descriptor(&id).unwrap().clone();
    descriptor.notification = Some(ExtensionNotificationDescriptor {
        name: PROXY_NOTICE.to_owned(),
        direction: ExtensionDirection::ServerToClient,
        activation_proof: None,
    });
    descriptor.stdio_correlation = Some(fastmcp_rust::StdioCorrelationDescriptor {
        metadata_key: PROXY_NOTICE_OWNER.to_owned(),
        methods: vec![PROXY_NOTICE.to_owned()],
        direction: ExtensionDirection::ServerToClient,
        codec: fastmcp_rust::StdioCorrelationCodec::RequestId,
    });
    let mut registry = ExtensionDescriptorRegistry::new();
    registry.register(descriptor).unwrap();
    discovery.extensions.retain(|extension, _| extension == &id);
    (id, registry, discovery)
}

async fn notice_client(cx: &Cx, endpoint: CanonicalHttpUrl) -> modern::HttpClient {
    let (_, registry, discovery) = notice_client_configuration();
    modern::ClientBuilder::new()
        .extension_registry(registry, discovery, || accept_settings)
        .unwrap()
        .connect_http_with_cx(cx, endpoint)
        .await
        .unwrap()
}

async fn http_notice(cx: &Cx, execution: &mut ModernHttpExtensionExecution, value: u32) {
    let Some(ModernHttpExtensionEvent::ExtensionNotification { notification, raw_params }) =
        execution.next_event(cx).await.unwrap()
    else {
        panic!("the forwarded notice must arrive before the terminal result");
    };
    assert_eq!(notification.method, PROXY_NOTICE);
    assert!(notification.id.is_none());
    let expected = json!({"value": value});
    assert_eq!(notification.params, Some(expected.clone()));
    assert_eq!(raw_params, Some(serde_json::to_string(&expected).unwrap()));
}

#[test]
fn typed_http_notification_proxy_streams_before_terminal_and_cancel_keeps_sibling() {
    interrupt_notification_proxy(false);
}

#[test]
fn typed_http_notification_proxy_streams_before_terminal_and_drop_keeps_sibling() {
    interrupt_notification_proxy(true);
}

fn interrupt_notification_proxy(drop_request: bool) {
    let observations = Arc::new(NotificationObservations::default());
    let retained = Arc::clone(&observations);
    let server = modern::ServerBuilder::new("streaming-proxy-producer", "1")
        .extension(notice_producer::<ScaleResponse>(Arc::clone(&observations), false))
        .unwrap();
    run_http_test(server, move |cx, endpoint| async move {
        let upstream = connect_upstream(
            &cx,
            endpoint,
            notice_producer::<ScaleResponse>(Arc::new(NotificationObservations::default()), false),
        )
        .await;
        let gateway = modern::ServerBuilder::new("streaming-proxy-gateway", "1")
            .extension(notice_gateway::<ScaleResponse>(upstream))
            .unwrap();
        with_http_server(&cx, gateway, |endpoint| async {
            let client = notice_client(&cx, endpoint).await;
            let id = ExtensionId::parse(EXTENSION).unwrap();
            let mut held = client
                .execute_final_extension(&cx, &id, METHOD, json!({"value": 7}), limits())
                .unwrap();
            http_notice(&cx, &mut held, 21).await;
            assert_eq!(observations.completed.load(Ordering::SeqCst), 0);
            let mut sibling = client
                .execute_final_extension(&cx, &id, METHOD, json!({"value": 11}), limits())
                .unwrap();
            http_notice(&cx, &mut sibling, 33).await;
            assert_eq!(terminal(&cx, &mut sibling).await, json!({"value": 33}));
            assert_eq!(observations.abandoned.load(Ordering::SeqCst), 0);
            if drop_request {
                drop(held);
            } else {
                assert!(held.control().cancel());
                held.next_event(&cx).await.expect_err("cancellation retires the live stream");
                drop(held);
            }
            asupersync::time::timeout(cx.now(), Duration::from_secs(2), async {
                while observations.abandoned.load(Ordering::SeqCst) == 0 {
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("both HTTP streams settle before listener shutdown");
            let mut following = client
                .execute_final_extension(&cx, &id, METHOD, json!({"value": 5}), limits())
                .unwrap();
            http_notice(&cx, &mut following, 15).await;
            assert_eq!(terminal(&cx, &mut following).await, json!({"value": 15}));
            assert!(cx.checkpoint().is_ok());
        })
        .await;
    });
    assert_eq!(retained.started.load(Ordering::SeqCst), 3);
    assert_eq!(retained.completed.load(Ordering::SeqCst), 2);
    assert_eq!(retained.abandoned.load(Ordering::SeqCst), 1);
}

#[test]
fn typed_http_notification_proxy_reconstructs_memory_request_owners() {
    let server = modern::ServerBuilder::new("notice-owner-producer", "1")
        .extension(notice_producer::<ScaleResponse>(
            Arc::new(NotificationObservations::default()), false,
        ))
        .unwrap();
    run_http_test(server, |cx, endpoint| async move {
        let upstream = connect_upstream(
            &cx,
            endpoint,
            notice_producer::<ScaleResponse>(Arc::new(NotificationObservations::default()), false),
        )
        .await;
        let server = modern::ServerBuilder::new("notice-owner-gateway", "1")
            .extension(notice_gateway::<ScaleResponse>(upstream))
            .unwrap()
            .try_build()
            .unwrap();
        let (mut peer, transport) = create_memory_transport_pair_with_capacity(8);
        let mut serving = cx
            .spawn(move |server_cx| async move {
                server.serve_memory(&server_cx, transport).await
            })
            .unwrap();
        for (owner, value) in [("downstream-five", 5), ("downstream-eleven", 11)] {
            let JsonRpcMessage::Request(mut frame) =
                request(1, Some(json!({"version": 1})), json!(value))
            else {
                unreachable!()
            };
            frame.id = Some(RequestId::String(owner.to_owned()));
            peer.send_async(&cx, &JsonRpcMessage::Request(frame)).await.unwrap();
        }
        let mut notices = BTreeMap::new();
        let mut results = BTreeMap::new();
        for _ in 0..4 {
            match peer.recv_async(&cx).await.unwrap() {
                JsonRpcMessage::Request(notification) => {
                    assert_eq!(notification.method, PROXY_NOTICE);
                    assert!(notification.id.is_none());
                    let parameters = notification.params.unwrap();
                    let owner = parameters["_meta"][PROXY_NOTICE_OWNER].as_str().unwrap();
                    assert_eq!(parameters["_meta"], json!({PROXY_NOTICE_OWNER: owner}));
                    assert!(notices.insert(owner.to_owned(), parameters["value"].clone()).is_none());
                }
                JsonRpcMessage::Response(response) => {
                    assert!(response.error.is_none());
                    let Some(RequestId::String(owner)) = response.id else {
                        panic!("the downstream response must retain its own string ID");
                    };
                    assert!(results.insert(owner, response.result.unwrap()["value"].clone()).is_none());
                }
            }
        }
        let expected = BTreeMap::from([
            ("downstream-five".to_owned(), json!(15)),
            ("downstream-eleven".to_owned(), json!(33)),
        ]);
        assert_eq!(notices, expected);
        assert_eq!(results, expected);
        let (mut input, output) = peer.into_split();
        drop(output);
        assert!(matches!(input.recv_async(&cx).await, Err(TransportError::Closed)));
        serving.join(&cx).await.unwrap().unwrap();
    });
}

#[test]
fn typed_http_notification_proxy_requires_a_matching_codec_and_live_sink_before_effects() {
    let observations = Arc::new(NotificationObservations::default());
    let retained = Arc::clone(&observations);
    let server = modern::ServerBuilder::new("notice-admission-producer", "1")
        .extension(notice_producer::<ScaleResponse>(observations, false))
        .unwrap();
    run_http_test(server, move |cx, endpoint| async move {
        let upstream = connect_upstream(
            &cx,
            endpoint,
            notice_producer::<ScaleResponse>(Arc::new(NotificationObservations::default()), false),
        )
        .await;
        assert!(
            builder().typed_http_proxy_request::<ScaleRequest, ScaleResponse>(
                METHOD, "scale-params-v1", "scale-result-v1", upstream.clone(),
            ).is_err(),
            "the existing request-only API must keep refusing streaming contracts"
        );
        assert!(
            builder()
                .typed_request_notification::<ScaleResponse>(
                    PROXY_NOTICE, "proxy-notice-v1", PROXY_NOTICE_OWNER,
                )
                .unwrap()
                .typed_http_proxy_request_with_notifications::<ScaleRequest, ScaleResponse, Echo>(
                    METHOD, "scale-params-v1", "scale-result-v1", upstream.clone(),
                )
                .is_err(),
            "a similarly named generic parameter cannot replace the declared schema"
        );
        let server = fastmcp_server::ServerBuilder::new("notice-sink-admission", "1")
            .protocol_policy(fastmcp_rust::ProtocolPolicy::ModernOnly)
            .unwrap()
            .extension(notice_gateway::<ScaleResponse>(upstream))
            .unwrap()
            .try_build()
            .unwrap();
        let discovery = ClientExtensionDiscovery {
            extensions: BTreeMap::from([(
                ExtensionId::parse(EXTENSION).unwrap(),
                ExtensionSettings::new(json!({"version": 1})).unwrap(),
            )]),
        };
        let negotiated = server.negotiate_extensions(&discovery).unwrap();
        let JsonRpcMessage::Request(mut frame) =
            request(1, Some(json!({"version": 1})), json!(5))
        else {
            unreachable!()
        };
        frame.params.as_mut().unwrap()["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
            json!({"extensions": {(EXTENSION): {"version": 1}}});
        let context = McpContext::new(cx.clone(), 1);
        let error = server
            .dispatch_negotiated_extension_async(&context, &negotiated, &frame)
            .await
            .expect_err("direct dispatch has no request-owned output transport");
        assert_eq!(error.code, fastmcp_rust::McpErrorCode::InvalidRequest);
        assert_eq!(retained.started.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn typed_http_notification_proxy_rejects_remote_schema_violation_and_preserves_siblings() {
    // The remote peer advertises the same settings but emits a wider payload
    // than our locally compiled contract permits. Its own producer is valid.
    let server = modern::ServerBuilder::new("loose-notice-producer", "1")
        .extension(notice_producer::<serde_json::Value>(
            Arc::new(NotificationObservations::default()), true,
        ))
        .unwrap();
    run_http_test(server, |cx, endpoint| async move {
        let upstream = connect_upstream(
            &cx,
            endpoint,
            notice_producer::<ScaleResponse>(Arc::new(NotificationObservations::default()), false),
        )
        .await;
        let server = modern::ServerBuilder::new("strict-notice-gateway", "1")
            .extension(notice_gateway::<ScaleResponse>(upstream))
            .unwrap();
        with_http_server(&cx, server, |endpoint| async {
            let client = notice_client(&cx, endpoint).await;
            let id = ExtensionId::parse(EXTENSION).unwrap();
            let mut invalid = client
                .execute_final_extension(&cx, &id, METHOD, json!({"value": 13}), limits())
                .unwrap();
            invalid.next_event(&cx).await
                .expect_err("bad typed notification is never published downstream");
            let mut sibling = client
                .execute_final_extension(&cx, &id, METHOD, json!({"value": 11}), limits())
                .unwrap();
            http_notice(&cx, &mut sibling, 33).await;
            assert_eq!(terminal(&cx, &mut sibling).await, json!({"value": 33}));
        })
        .await;
    });
}

#[test]
fn typed_http_notification_proxy_rejects_metadata_synthesized_by_notification_codec() {
    let server = modern::ServerBuilder::new("notice-serialization-producer", "1")
        .extension(notice_producer::<ForgedRequest>(
            Arc::new(NotificationObservations::default()), false,
        ))
        .unwrap();
    run_http_test(server, |cx, endpoint| async move {
        let upstream = connect_upstream(
            &cx,
            endpoint,
            notice_producer::<ForgedRequest>(Arc::new(NotificationObservations::default()), false),
        )
        .await;
        let server = modern::ServerBuilder::new("notice-serialization-gateway", "1")
            .extension(notice_gateway::<ForgedRequest>(upstream))
            .unwrap();
        with_http_server(&cx, server, |endpoint| async {
            let client = notice_client(&cx, endpoint).await;
            let mut invalid = client
                .execute_final_extension(
                    &cx, &ExtensionId::parse(EXTENSION).unwrap(), METHOD,
                    json!({"value": 5}), limits(),
                )
                .unwrap();
            invalid.next_event(&cx).await
                .expect_err("typed notification cannot recreate upstream authority");
        })
        .await;
    });
}
