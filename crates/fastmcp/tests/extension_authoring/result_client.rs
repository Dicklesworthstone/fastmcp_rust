//! Real typed extension producers and the shipped HTTP and memory clients.

#[cfg(unix)]
#[path = "result_client/stdio.rs"]
mod stdio;

use std::collections::BTreeMap;

use super::*;
use fastmcp_rust::{
    CanonicalHttpUrl, ClientExtensionDiscovery, ExtensionDescriptor, ExtensionDescriptorRegistry,
    ExtensionDirection, ExtensionFallbackPolicy, ExtensionHttpEraDisposition, ExtensionId,
    ExtensionMethodDescriptor, ExtensionNegotiationError, ExtensionNegotiationResolver,
    ExtensionNotificationDescriptor, ExtensionSettings, ExtensionSettingsSchema,
    NotificationActivationProofDescriptor, NotificationActivationProofLocation,
};

fn client_configuration() -> (
    ExtensionId,
    ExtensionDescriptorRegistry,
    ClientExtensionDiscovery,
) {
    client_configuration_with_notifications(false)
}

fn client_configuration_with_notifications(
    notifications: bool,
) -> (
    ExtensionId,
    ExtensionDescriptorRegistry,
    ClientExtensionDiscovery,
) {
    let id = ExtensionId::parse(EXTENSION).unwrap();
    let mut descriptors = ExtensionDescriptorRegistry::new();
    descriptors
        .register(ExtensionDescriptor {
            id: id.clone(),
            client_settings: ExtensionSettingsSchema {
                schema_id: "typed-math-client-v1".to_owned(),
                codec_id: "typed-math-client-codec-v1".to_owned(),
            },
            server_settings: ExtensionSettingsSchema {
                schema_id: "typed-math-server-v1".to_owned(),
                codec_id: "typed-math-server-codec-v1".to_owned(),
            },
            resolver: ExtensionNegotiationResolver {
                id: "typed-math-client-resolver-v1".to_owned(),
                version: 1,
                fallback: ExtensionFallbackPolicy::RejectOneSided,
            },
            method: Some(ExtensionMethodDescriptor {
                name: METHOD.to_owned(),
                direction: ExtensionDirection::ClientToServer,
                http_era_disposition: Some(ExtensionHttpEraDisposition::ModernExclusive),
                legacy_fallback: false,
            }),
            notification: notifications.then(|| ExtensionNotificationDescriptor {
                name: NOTIFICATION.to_owned(),
                direction: ExtensionDirection::ClientToServer,
                activation_proof: Some(NotificationActivationProofDescriptor::SelfContained {
                    location: NotificationActivationProofLocation::Metadata,
                    key: ACTIVATION.to_owned(),
                }),
            }),
            result_discriminator: None,
            routing_headers: Vec::new(),
            stdio_correlation: None,
        })
        .unwrap();
    let discovery = ClientExtensionDiscovery {
        extensions: BTreeMap::from([(
            id.clone(),
            ExtensionSettings::new(json!({"version": 1})).unwrap(),
        )]),
    };
    // Mirror the existing facade fixture's explicitly selected Tasks profile;
    // its descriptor and advertisement are separate from the math capability.
    #[cfg(feature = "tasks")]
    let discovery = {
        let mut discovery = discovery;
        let tasks = fastmcp_rust::register_official_tasks_extension(&mut descriptors).unwrap();
        discovery
            .extensions
            .insert(tasks, fastmcp_rust::official_tasks_empty_settings());
        discovery
    };
    (id, descriptors, discovery)
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the resolver contract returns a Result"
)]
fn accept_settings(
    _descriptor: &ExtensionDescriptor,
    _client: &ExtensionSettings,
    server: &ExtensionSettings,
) -> Result<ExtensionSettings, ExtensionNegotiationError> {
    Ok(server.clone())
}

#[test]
fn typed_extension_http_client_preserves_payload_only_result() {
    let calls = Arc::new(AtomicUsize::new(0));
    let retained = Arc::clone(&calls);
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let server = modern::ServerBuilder::new("typed-result-producer", "1.0")
                .extension(registration(calls))
                .unwrap()
                .try_build()
                .unwrap();
            let bound = server.bind_http(&cx, "127.0.0.1:0").await.unwrap();
            let endpoint =
                CanonicalHttpUrl::parse(&format!("http://{}/mcp", bound.local_addr().unwrap()))
                    .unwrap();
            let (ready, mut receiver) = asupersync::channel::oneshot::channel();
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    ready.send(&server_cx, server_cx.clone()).unwrap();
                    bound.serve(&server_cx).await
                })
                .unwrap();
            let server_cx = receiver.recv(&cx).await.unwrap();
            let (id, descriptors, discovery) = client_configuration();
            let mut client = modern::ClientBuilder::new()
                .extension_registry(descriptors, discovery, || accept_settings)
                .unwrap()
                .connect_http_with_cx(&cx, endpoint)
                .await
                .unwrap();

            for value in [7, 11] {
                let result = client
                    .request_final_extension(&cx, &id, METHOD, json!({"value": value}))
                    .await
                    .expect("the typed producer's valid object reaches the real HTTP client");
                assert_eq!(result, json!({"value": value * 3}));
                assert!(result.get("resultType").is_none());
                let typed: ScaleResponse = serde_json::from_value(result).unwrap();
                assert_eq!(typed.value, value * 3);
            }
            client
                .request_final_extension(&cx, &id, "tools/list", json!({}))
                .await
                .expect_err("a negotiated extension cannot borrow a core method");
            drop(client);
            server_cx.cancel_with(
                asupersync::types::CancelKind::Shutdown,
                Some("extension result exchange complete"),
            );
            assert!(matches!(
                serving.join(&cx).await.unwrap().unwrap(),
                fastmcp_rust::HttpServerShutdown::Quiescent
            ));
        })
        .await
        .expect("bounded exchange and caller-owned shutdown");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    assert_eq!(
        retained.load(Ordering::SeqCst),
        2,
        "the two valid calls execute; the forbidden core-method near-match does not"
    );
}

struct CancellableScaleHandler(Arc<NotificationObservations>);

impl fastmcp_rust::extensions::authoring::ExtensionHandler<ScaleRequest, ScaleResponse, Settings>
    for CancellableScaleHandler
{
    fn handle<'a>(
        &'a self,
        context: ExtensionContext<'a, Settings>,
        request: ScaleRequest,
    ) -> fastmcp_rust::BoxFuture<'a, McpResult<ScaleResponse>> {
        Box::pin(async move {
            let mut guard = NotificationGuard {
                observations: Arc::clone(&self.0),
                completed: false,
            };
            self.0.started.fetch_add(1, Ordering::SeqCst);
            if request.value == 7 {
                std::future::pending::<()>().await;
            }
            asupersync::runtime::yield_now().await;
            context.checkpoint()?;
            self.0.completed.fetch_add(1, Ordering::SeqCst);
            guard.completed = true;
            Ok(ScaleResponse {
                value: request.value * context.settings().multiplier,
            })
        })
    }
}

#[test]
fn typed_extension_http_cancellation_settles_handler_and_preserves_client() {
    use fastmcp_rust::{McpErrorCode, McpRequestCancellation};
    use std::future::Future;
    use std::task::Poll;

    let observations = Arc::new(NotificationObservations::default());
    let retained = Arc::clone(&observations);
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let registration = builder()
                .typed_request(
                    METHOD,
                    "scale-params-v1",
                    "scale-result-v1",
                    CancellableScaleHandler(Arc::clone(&observations)),
                )
                .unwrap()
                .build()
                .unwrap();
            let server = modern::ServerBuilder::new("cancellable-typed-result", "1.0")
                .extension(registration)
                .unwrap()
                .try_build()
                .unwrap();
            let bound = server.bind_http(&cx, "127.0.0.1:0").await.unwrap();
            let endpoint =
                CanonicalHttpUrl::parse(&format!("http://{}/mcp", bound.local_addr().unwrap()))
                    .unwrap();
            let (ready, mut receiver) = asupersync::channel::oneshot::channel();
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    ready.send(&server_cx, server_cx.clone()).unwrap();
                    bound.serve(&server_cx).await
                })
                .unwrap();
            let server_cx = receiver.recv(&cx).await.unwrap();
            let (id, descriptors, discovery) = client_configuration();
            let mut client = modern::ClientBuilder::new()
                .extension_registry(descriptors, discovery, || accept_settings)
                .unwrap()
                .connect_http_with_cx(&cx, endpoint)
                .await
                .unwrap();

            let cancelled = McpRequestCancellation::new();
            cancelled.cancel();
            let error = client
                .request_final_extension_with_cancellation(
                    &cx,
                    &cancelled,
                    &id,
                    METHOD,
                    json!({"value": 5}),
                )
                .await
                .unwrap_err();
            assert!(matches!(error, fastmcp_rust::HttpClientError::CoreResult(error)
                if error.code == McpErrorCode::RequestCancelled));
            assert_eq!(observations.started.load(Ordering::SeqCst), 0);

            let cancellation = McpRequestCancellation::new();
            let mut request = Box::pin(client.request_final_extension_with_cancellation(
                &cx,
                &cancellation,
                &id,
                METHOD,
                json!({"value": 7}),
            ));
            while observations.started.load(Ordering::SeqCst) == 0 {
                assert!(
                    std::future::poll_fn(|task| Poll::Ready(request.as_mut().poll(task)))
                        .await
                        .is_pending(),
                    "the typed handler must start before cancellation"
                );
                asupersync::runtime::yield_now().await;
            }
            cancellation.cancel();
            let error = asupersync::time::timeout(cx.now(), Duration::from_secs(2), request)
                .await
                .expect("cancellation does not wait for the handler's result")
                .unwrap_err();
            assert!(matches!(
                error,
                fastmcp_rust::HttpClientError::Connection(
                    fastmcp_rust::ClientHttpConnectionError::Modern(
                        fastmcp_rust::ModernHttpClientError::Executor(
                            fastmcp_rust::ModernHttpExecutorError::Cancelled
                        )
                    )
                )
            ));
            assert!(cx.checkpoint().is_ok());
            let live = McpRequestCancellation::new();
            let result = client
                .request_final_extension_with_cancellation(
                    &cx,
                    &live,
                    &id,
                    METHOD,
                    json!({"value": 11}),
                )
                .await
                .expect("the same client remains usable with fresh request custody");
            assert_eq!(result, json!({"value": 33}));
            assert!(!live.is_cancel_requested());
            asupersync::time::timeout(cx.now(), Duration::from_secs(2), async {
                while observations.abandoned.load(Ordering::SeqCst) == 0 {
                    asupersync::runtime::yield_now().await;
                }
            })
            .await
            .expect("disconnect settles the cancelled typed handler before listener shutdown");
            drop(client);
            server_cx.cancel_with(
                asupersync::types::CancelKind::Shutdown,
                Some("typed extension cancellation complete"),
            );
            assert!(matches!(
                serving.join(&cx).await.unwrap().unwrap(),
                fastmcp_rust::HttpServerShutdown::Quiescent
            ));
        })
        .await
        .expect("bounded typed extension cancellation and cleanup");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    assert_eq!(retained.started.load(Ordering::SeqCst), 2);
    assert_eq!(retained.completed.load(Ordering::SeqCst), 1);
    assert_eq!(retained.abandoned.load(Ordering::SeqCst), 1);
}

fn duplex_registration(
    calls: Arc<AtomicUsize>,
    observations: Arc<NotificationObservations>,
) -> ExtensionRegistration {
    let authorization = Arc::clone(&observations);
    builder()
        .typed_request_sync(
            METHOD,
            "scale-params-v1",
            "scale-result-v1",
            move |context: ExtensionContext<'_, Settings>, request: ScaleRequest| {
                context.checkpoint()?;
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(ScaleResponse {
                    value: request.value * context.settings().multiplier,
                })
            },
        )
        .unwrap()
        .typed_notification(
            NOTIFICATION,
            "scaled-notification-v1",
            ACTIVATION,
            move |notification: &ScaleNotification| {
                authorization.authorized.fetch_add(1, Ordering::SeqCst);
                if notification.value == 13 {
                    return Err(McpError::new(
                        fastmcp_rust::McpErrorCode::ResourceForbidden,
                        "notification operation denied",
                    ));
                }
                Ok(())
            },
            ScaleNotificationHandler(observations),
        )
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn typed_extension_memory_client_multiplexes_requests_and_notifications() {
    use fastmcp_rust::{
        ClientInfo, CoreResult, FinalCoreResult, McpRequestCancellation, MemoryExtensionEvent,
        MemoryRequestEvent,
    };

    let calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = Arc::clone(&calls);
    let observations = Arc::new(NotificationObservations::default());
    let observed = Arc::clone(&observations);
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), async {
            let server = modern::ServerBuilder::new("typed-memory-client", "1.0")
                .extension(duplex_registration(calls, Arc::clone(&observations)))
                .unwrap()
                .try_build()
                .unwrap();
            let (transport, peer) = create_memory_transport_pair_with_capacity(1);
            let mut serving = cx
                .spawn(move |server_cx| async move { server.serve_memory(&server_cx, peer).await })
                .unwrap();
            let (id, descriptors, discovery) = client_configuration_with_notifications(true);
            // Memory Tasks is an explicit client policy, independent of this
            // generic extension's descriptor, settings, and result authority.
            #[cfg(feature = "tasks")]
            let discovery = {
                let mut discovery = discovery;
                discovery
                    .extensions
                    .remove(&ExtensionId::parse("io.modelcontextprotocol/tasks").unwrap());
                discovery
            };
            let builder = modern::MemoryClient::builder(ClientInfo {
                name: "typed-memory-consumer".to_owned(),
                version: "1.0".to_owned(),
            })
            .extension_registry(descriptors, discovery, || accept_settings)
            .unwrap();
            #[cfg(feature = "tasks")]
            let builder = builder.with_tasks();
            let mut client = builder.connect(&cx, transport).await.unwrap();
            #[cfg(feature = "tasks")]
            assert!(client.tasks_active());
            let cancellation = McpRequestCancellation::new();
            client
                .notify_final_extension(
                    &cx,
                    &cancellation,
                    &id,
                    NOTIFICATION,
                    json!({"value": 7, "hold": false}),
                )
                .await
                .unwrap();
            let mut extension = client
                .execute_final_extension(&cx, &cancellation, &id, METHOD, json!({"value": 7}))
                .await
                .unwrap();
            assert_eq!(extension.request_id(), &RequestId::Number(2));
            let mut core = client
                .execute_core(&cx, &cancellation, "tools/list", json!({}))
                .await
                .unwrap();
            assert_eq!(core.request_id(), &RequestId::Number(3));

            // These stale request fields cannot replace the fresh notification
            // proof emitted from this client's immutable local configuration.
            client
                .notify_final_extension(
                    &cx,
                    &cancellation,
                    &id,
                    NOTIFICATION,
                    json!({"value": 11, "hold": false, "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                        "io.modelcontextprotocol/clientCapabilities": {
                            "extensions": {(EXTENSION): {"version": 2}}
                        }
                    }}),
                )
                .await
                .unwrap();
            client
                .notify_final_extension(
                    &cx,
                    &cancellation,
                    &id,
                    NOTIFICATION,
                    json!({"value": 17, "hold": false, "_meta": {(ACTIVATION): {"version": 2}}}),
                )
                .await
                .expect_err("a caller cannot override the configured notification proof");
            for value in [json!("wrong-type"), json!(13)] {
                client
                    .notify_final_extension(
                        &cx,
                        &cancellation,
                        &id,
                        NOTIFICATION,
                        json!({"value": value, "hold": false}),
                    )
                    .await
                    .expect("publication succeeds; stream notifications have no response");
            }
            let Some(MemoryRequestEvent::Result(result)) = client
                .next_event(&cx, &cancellation, &mut core)
                .await
                .unwrap()
            else {
                panic!("the core sibling retains its own terminal result");
            };
            assert!(matches!(
                *result,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            let Some(MemoryExtensionEvent::Result(result)) = client
                .next_extension_event(&cx, &cancellation, &mut extension)
                .await
                .unwrap()
            else {
                panic!("the extension retains its own terminal result");
            };
            assert_eq!(result, json!({"value": 21}));
            assert_eq!(
                serde_json::from_str::<fastmcp_rust::JsonValue>(
                    extension.raw_result_source().unwrap()
                )
                .unwrap(),
                result,
            );
            assert!(
                client
                    .next_extension_event(&cx, &cancellation, &mut extension)
                    .await
                    .unwrap()
                    .is_none()
            );
            client
                .request_final_extension(&cx, &cancellation, &id, METHOD, json!({"value": "bad"}))
                .await
                .expect_err("the typed producer rejects invalid payloads without executing them");
            assert_eq!(
                client
                    .request_final_extension(&cx, &cancellation, &id, METHOD, json!({"value": 5}))
                    .await
                    .unwrap(),
                json!({"value": 15}),
                "a rejected sibling does not poison the connection",
            );
            while observations.completed.load(Ordering::SeqCst) < 2
                || observations.authorized.load(Ordering::SeqCst) < 3
            {
                asupersync::runtime::yield_now().await;
            }
            assert!(client.take_server_notifications().is_empty());
            client.close(&cx).unwrap();
            serving.join(&cx).await.unwrap().unwrap();
            assert!(cx.checkpoint().is_ok());
        })
        .await
        .expect("capacity-one memory client and server complete on their caller runtime");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    assert_eq!(observed_calls.load(Ordering::SeqCst), 2);
    assert_eq!(observed.authorized.load(Ordering::SeqCst), 3);
    assert_eq!(observed.started.load(Ordering::SeqCst), 2);
    assert_eq!(observed.completed.load(Ordering::SeqCst), 2);
    assert_eq!(observed.total.load(Ordering::SeqCst), 54);
    assert_eq!(observed.abandoned.load(Ordering::SeqCst), 0);
}

#[test]
fn typed_notification_modern_http_facade_acknowledges_completed_callbacks() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = Arc::clone(&calls);
    let observations = Arc::new(NotificationObservations::default());
    let observed = Arc::clone(&observations);
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let server = modern::ServerBuilder::new("typed-http-notify-client", "1.0")
                .extension(duplex_registration(calls, Arc::clone(&observations)))
                .unwrap()
                .try_build()
                .unwrap();
            let bound = server.bind_http(&cx, "127.0.0.1:0").await.unwrap();
            let endpoint =
                CanonicalHttpUrl::parse(&format!("http://{}/mcp", bound.local_addr().unwrap(),))
                    .unwrap();
            let (ready, mut receiver) = asupersync::channel::oneshot::channel();
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    ready.send(&server_cx, server_cx.clone()).unwrap();
                    bound.serve(&server_cx).await
                })
                .unwrap();
            let server_cx = receiver.recv(&cx).await.unwrap();
            let (id, descriptors, discovery) = client_configuration_with_notifications(true);
            let mut client = modern::ClientBuilder::new()
                .extension_registry(descriptors, discovery, || accept_settings)
                .unwrap()
                .connect_http_with_cx(&cx, endpoint)
                .await
                .unwrap();
            for value in [7, 11] {
                client
                    .notify_final_extension(
                        &cx,
                        &id,
                        NOTIFICATION,
                        json!({"value": value, "hold": false}),
                    )
                    .await
                    .expect("the public facade accepts the server's empty HTTP 202");
            }
            assert_eq!(observations.completed.load(Ordering::SeqCst), 2);
            for parameters in [
                json!({"value": 13, "hold": false}),
                json!({"value": "bad", "hold": false}),
                json!({"value": 17, "hold": false, "_meta": {(ACTIVATION): {"version": 2}}}),
            ] {
                client
                    .notify_final_extension(&cx, &id, NOTIFICATION, parameters)
                    .await
                    .expect_err("schema, policy and local proof refusals remain observable");
            }
            assert_eq!(
                client
                    .request_final_extension(&cx, &id, METHOD, json!({"value": 5}))
                    .await
                    .unwrap(),
                json!({"value": 15}),
            );
            drop(client);
            server_cx.cancel_with(
                asupersync::types::CancelKind::Shutdown,
                Some("public notification client exchange complete"),
            );
            assert!(matches!(
                serving.join(&cx).await.unwrap().unwrap(),
                fastmcp_rust::HttpServerShutdown::Quiescent,
            ));
        })
        .await
        .expect("bounded public HTTP notification and request exchange");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    assert_eq!(observed_calls.load(Ordering::SeqCst), 1);
    assert_eq!(observed.authorized.load(Ordering::SeqCst), 3);
    assert_eq!(observed.completed.load(Ordering::SeqCst), 2);
    assert_eq!(observed.total.load(Ordering::SeqCst), 54);
    assert_eq!(observed.abandoned.load(Ordering::SeqCst), 0);
}
