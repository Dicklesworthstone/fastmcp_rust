//! Live transport coverage for the restricted extension authoring facade.
//! These tests use the shipped server pump on an application-owned runtime.

#![cfg(feature = "extension-authoring")]
#![recursion_limit = "512"]

#[path = "extension_authoring/result_client.rs"]
mod result_client;

#[path = "extension_authoring/request_notifications.rs"]
mod request_notifications;

#[cfg(all(feature = "proxy", feature = "websocket-experimental"))]
mod websocket_proxy {
    use super::*;

    struct HeldScaleHandler {
        started: Arc<AtomicUsize>,
        release: Arc<asupersync::sync::Notify>,
    }

    impl
        fastmcp_rust::extensions::authoring::ExtensionHandler<ScaleRequest, ScaleResponse, Settings>
        for HeldScaleHandler
    {
        fn handle<'a>(
            &'a self,
            context: ExtensionContext<'a, Settings>,
            request: ScaleRequest,
        ) -> fastmcp_rust::BoxFuture<'a, McpResult<ScaleResponse>> {
            Box::pin(async move {
                self.started.fetch_add(1, Ordering::SeqCst);
                self.release.notified().await;
                context.checkpoint()?;
                Ok(ScaleResponse {
                    value: request.value * context.settings().multiplier,
                })
            })
        }
    }

    #[test]
    fn typed_websocket_proxy_cancelled_close_bounds_contention_and_retries_after_release() {
        use std::future::Future;
        use std::task::Poll;

        let started = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(asupersync::sync::Notify::new());
        let upstream_registration = builder()
            .typed_request(
                METHOD,
                "scale-params-v1",
                "scale-result-v1",
                HeldScaleHandler {
                    started: Arc::clone(&started),
                    release: Arc::clone(&release),
                },
            )
            .unwrap()
            .build()
            .unwrap();
        with_upstream(upstream_registration, move |cx, address| async move {
            let declaration_calls = Arc::new(AtomicUsize::new(0));
            let transport =
                fastmcp_rust::AsyncWsClientTransport::connect(&cx, &format!("ws://{address}/mcp"))
                    .await
                    .unwrap();
            let upstream = modern::ClientBuilder::new()
                .connect_extension_websocket_upstream_with_cx(
                    &cx,
                    transport,
                    registration(Arc::clone(&declaration_calls)),
                    &ClientSettings { version: 1 },
                )
                .await
                .unwrap();
            let gateway_registration = builder()
                .typed_websocket_proxy_request::<ScaleRequest, ScaleResponse, _>(
                    METHOD,
                    "scale-params-v1",
                    "scale-result-v1",
                    upstream.clone(),
                )
                .unwrap()
                .build()
                .unwrap();
            let server = modern::ServerBuilder::new("typed-websocket-close-gateway", "1")
                .extension(gateway_registration)
                .unwrap()
                .try_build()
                .unwrap();
            let (mut peer, transport) = create_memory_transport_pair_with_capacity(1);
            let mut serving =
                cx.spawn(move |server_cx| async move {
                    server.serve_memory(&server_cx, transport).await
                })
                .unwrap();
            peer.send_async(&cx, &request(906, Some(json!({"version": 1})), json!(7)))
                .await
                .unwrap();
            while started.load(Ordering::SeqCst) == 0 {
                asupersync::runtime::yield_now().await;
            }
            let closing = cx
                .open_child_region(asupersync::cx::child_region::ChildRegionSpec::inherit())
                .await
                .unwrap();
            closing.cx().cancel_with(
                asupersync::types::CancelKind::Shutdown,
                Some("close while a forwarded request holds the connection"),
            );
            let error = asupersync::time::timeout(
                cx.now(),
                Duration::from_secs(2),
                upstream.close(closing.cx()),
            )
            .await
            .expect("busy cleanup acquisition must retain its finite bound")
            .unwrap_err();
            assert_eq!(
                error.message,
                "WebSocket extension upstream close acquisition timed out"
            );
            assert!(closing.cx().is_cancel_requested());
            assert!(cx.checkpoint().is_ok());

            let mut retry = Box::pin(upstream.close(closing.cx()));
            assert!(
                std::future::poll_fn(|task| Poll::Ready(retry.as_mut().poll(task)))
                    .await
                    .is_pending(),
                "the cancelled caller must retain a cleanup waiter while busy"
            );
            release.notify_one();
            let (reply, closed) = {
                let mut incoming = Box::pin(response(&cx, &mut peer, 906));
                let mut reply = None;
                let mut closed = None;
                std::future::poll_fn(|task| {
                    if reply.is_none()
                        && let Poll::Ready(value) = incoming.as_mut().poll(task)
                    {
                        reply = Some(value);
                    }
                    if closed.is_none()
                        && let Poll::Ready(value) = retry.as_mut().poll(task)
                    {
                        closed = Some(value);
                    }
                    if reply.is_some() && closed.is_some() {
                        Poll::Ready((reply.take().unwrap(), closed.take().unwrap()))
                    } else {
                        Poll::Pending
                    }
                })
                .await
            };
            drop(retry);
            assert!(
                reply.error.is_none(),
                "cleanup must not cancel the active request: {reply:?}"
            );
            assert_eq!(reply.result.as_ref().unwrap()["value"], 21);
            closed.unwrap();
            assert!(closing.cx().is_cancel_requested());
            closing.close().await.unwrap();
            upstream.close(&cx).await.unwrap();
            assert_eq!(started.load(Ordering::SeqCst), 1);
            assert_eq!(declaration_calls.load(Ordering::SeqCst), 0);
            let (mut input, output) = peer.into_split();
            drop(output);
            assert!(matches!(
                input.recv_async(&cx).await,
                Err(TransportError::Closed)
            ));
            serving.join(&cx).await.unwrap().unwrap();
        });
    }

    fn with_upstream<F, Fut>(registration: ExtensionRegistration, exercise: F)
    where
        F: FnOnce(Cx, std::net::SocketAddr) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
                let server = modern::ServerBuilder::new("typed-websocket-upstream", "1")
                    .extension(registration)
                    .unwrap()
                    .try_build()
                    .unwrap();
                let bound = server.bind_websocket(&cx, "127.0.0.1:0").await.unwrap();
                let address = bound.local_addr().unwrap();
                let (ready, mut receiver) = asupersync::channel::oneshot::channel();
                let mut serving = cx
                    .spawn(move |server_cx| async move {
                        ready.send(&server_cx, server_cx.clone()).unwrap();
                        bound.serve(&server_cx).await
                    })
                    .unwrap();
                let server_cx = receiver.recv(&cx).await.unwrap();
                exercise(cx.clone(), address).await;
                server_cx.cancel_with(
                    asupersync::types::CancelKind::Shutdown,
                    Some("typed WebSocket proxy test complete"),
                );
                assert!(matches!(
                    serving.join(&cx).await.unwrap().unwrap(),
                    fastmcp_rust::WebSocketServerShutdown::Quiescent
                ));
                assert!(cx.checkpoint().is_ok());
            })
            .await
            .expect("bounded proxy exchange and native cleanup");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    async fn exchange(
        cx: &Cx,
        registration: ExtensionRegistration,
        requests: Vec<JsonRpcMessage>,
    ) -> Vec<JsonRpcResponse> {
        let server = modern::ServerBuilder::new("typed-websocket-gateway", "1")
            .extension(registration)
            .unwrap()
            .try_build()
            .unwrap();
        let (mut peer, transport) = create_memory_transport_pair_with_capacity(1);
        let mut serving = cx
            .spawn(move |server_cx| async move { server.serve_memory(&server_cx, transport).await })
            .unwrap();
        let mut replies = Vec::new();
        for message in requests {
            let JsonRpcMessage::Request(request) = &message else {
                panic!("request fixture expected");
            };
            let Some(RequestId::Number(id)) = request.id else {
                panic!("numbered request fixture expected");
            };
            peer.send_async(cx, &message).await.unwrap();
            replies.push(response(cx, &mut peer, id).await);
        }
        let (mut input, output) = peer.into_split();
        drop(output);
        assert!(matches!(
            input.recv_async(cx).await,
            Err(TransportError::Closed)
        ));
        serving.join(cx).await.unwrap().unwrap();
        replies
    }

    #[test]
    fn typed_websocket_proxy_revalidates_both_legs_and_reuses_its_native_connection() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        with_upstream(registration(calls), move |cx, address| async move {
            let declaration_calls = Arc::new(AtomicUsize::new(0));
            let transport =
                fastmcp_rust::AsyncWsClientTransport::connect(&cx, &format!("ws://{address}/mcp"))
                    .await
                    .unwrap();
            let upstream = modern::ClientBuilder::new()
                .client_info("typed-gateway-client", "1")
                .connect_extension_websocket_upstream_with_cx(
                    &cx,
                    transport,
                    registration(Arc::clone(&declaration_calls)),
                    &ClientSettings { version: 1 },
                )
                .await
                .unwrap();
            assert_eq!(upstream.descriptor().id(), EXTENSION);

            let different_schema = builder()
                .typed_websocket_proxy_request::<ScaleRequest, ScaleResponse, _>(
                    METHOD,
                    "different-scale-params-v1",
                    "scale-result-v1",
                    upstream.clone(),
                )
                .unwrap()
                .build();
            assert!(
                different_schema.is_err(),
                "the complete contract must agree"
            );
            assert!(
                builder()
                    .typed_request_notification::<ScaleResponse>(
                        "com.example/request-scaled",
                        "request-scaled-v1",
                        "com.example/request-id",
                    )
                    .unwrap()
                    .typed_websocket_proxy_request::<ScaleRequest, ScaleResponse, _>(
                        METHOD,
                        "scale-params-v1",
                        "scale-result-v1",
                        upstream.clone(),
                    )
                    .is_err(),
                "request-owned server notifications require a supported relay"
            );

            let gateway = builder()
                .typed_websocket_proxy_request::<ScaleRequest, ScaleResponse, _>(
                    METHOD,
                    "scale-params-v1",
                    "scale-result-v1",
                    upstream.clone(),
                )
                .unwrap()
                .build()
                .unwrap();
            let replies = exchange(
                &cx,
                gateway,
                vec![
                    request(900, Some(json!({"version": 1})), json!(7)),
                    request(901, Some(json!({"version": 2})), json!(7)),
                    request(902, None, json!(7)),
                    request(903, Some(json!({"version": 1})), json!("wrong-type")),
                    request(904, Some(json!({"version": 1})), json!(11)),
                ],
            )
            .await;
            assert_eq!(replies[0].result.as_ref().unwrap()["value"], 21);
            assert_eq!(replies[4].result.as_ref().unwrap()["value"], 33);
            for reply in &replies[1..4] {
                assert!(reply.error.is_some(), "{reply:?}");
                assert!(reply.result.is_none());
            }
            assert_eq!(observed.load(Ordering::SeqCst), 2);
            assert_eq!(declaration_calls.load(Ordering::SeqCst), 0);

            let mismatched = ExtensionBuilder::new(
                EXTENSION,
                1,
                "typed-math-client-v1",
                "typed-math-server-v1",
                ServerSettings {
                    version: 1,
                    multiplier: 4,
                },
                |client: ClientSettings, server: ServerSettings| {
                    if client.version != server.version {
                        return Err(McpError::invalid_params("incompatible math version"));
                    }
                    Ok(Settings {
                        multiplier: server.multiplier,
                    })
                },
            )
            .unwrap()
            .typed_websocket_proxy_request::<ScaleRequest, ScaleResponse, _>(
                METHOD,
                "scale-params-v1",
                "scale-result-v1",
                upstream.clone(),
            )
            .unwrap()
            .build()
            .unwrap();
            let replies = exchange(
                &cx,
                mismatched,
                vec![request(905, Some(json!({"version": 1})), json!(7))],
            )
            .await;
            assert!(
                replies[0].error.is_some(),
                "effective settings differ across legs"
            );
            assert_eq!(observed.load(Ordering::SeqCst), 2);
            let closing = cx
                .open_child_region(asupersync::cx::child_region::ChildRegionSpec::inherit())
                .await
                .unwrap();
            closing.cx().cancel_with(
                asupersync::types::CancelKind::Shutdown,
                Some("close an upstream after its caller was cancelled"),
            );
            upstream.close(closing.cx()).await.unwrap();
            assert!(closing.cx().is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
            closing.close().await.unwrap();
            upstream.close(&cx).await.unwrap();
        });
    }

    #[test]
    fn typed_websocket_proxy_notifications_require_current_proof_and_authorization() {
        let observations = Arc::new(NotificationObservations::default());
        let retained = Arc::clone(&observations);
        with_upstream(
            notification_registration(Arc::clone(&observations)),
            move |cx, address| async move {
                let declaration = Arc::new(NotificationObservations::default());
                let transport = fastmcp_rust::AsyncWsClientTransport::connect(
                    &cx,
                    &format!("ws://{address}/mcp"),
                )
                .await
                .unwrap();
                let upstream = modern::ClientBuilder::new()
                    .connect_extension_websocket_upstream_with_cx(
                        &cx,
                        transport,
                        notification_registration(Arc::clone(&declaration)),
                        &ClientSettings { version: 1 },
                    )
                    .await
                    .unwrap();
                let authorizations = Arc::new(AtomicUsize::new(0));
                let counted = Arc::clone(&authorizations);
                let registration = builder()
                    .typed_websocket_proxy_notification::<ScaleNotification, _, _>(
                        NOTIFICATION,
                        "scaled-notification-v1",
                        ACTIVATION,
                        move |notification| {
                            counted.fetch_add(1, Ordering::SeqCst);
                            if notification.value == 13 {
                                return Err(McpError::invalid_request("operation denied"));
                            }
                            Ok(())
                        },
                        upstream.clone(),
                    )
                    .unwrap()
                    .build()
                    .unwrap();
                let server = modern::ServerBuilder::new("typed-notification-gateway", "1")
                    .extension(registration)
                    .unwrap()
                    .try_build()
                    .unwrap();
                let (mut peer, transport) = create_memory_transport_pair_with_capacity(1);
                let mut serving = cx
                    .spawn(move |server_cx| async move {
                        server.serve_memory(&server_cx, transport).await
                    })
                    .unwrap();
                let valid = notification(7, false);
                let mut missing = valid.clone();
                missing["params"]["_meta"]
                    .as_object_mut()
                    .unwrap()
                    .remove(ACTIVATION);
                let mut incompatible = valid.clone();
                incompatible["params"]["_meta"][ACTIVATION]["version"] = json!(2);
                let mut malformed = valid.clone();
                malformed["params"]["value"] = json!("wrong-type");
                for value in [
                    valid,
                    missing,
                    incompatible,
                    malformed,
                    notification(13, false),
                ] {
                    let message: JsonRpcMessage =
                        fastmcp_rust::serde_json::from_value(value).unwrap();
                    peer.send_async(&cx, &message).await.unwrap();
                }
                // Authorization runs after schema validation and before activation-proof /
                // compatibility checks (lib.rs): `valid`, `missing`, `incompatible`, and
                // `notification(13)` invoke the authorizer (4), while `malformed` is rejected
                // before authorization and only `valid` (1) is forwarded upstream.
                while observations.completed.load(Ordering::SeqCst) < 1
                    || authorizations.load(Ordering::SeqCst) < 4
                {
                    asupersync::runtime::yield_now().await;
                }
                let (mut input, output) = peer.into_split();
                drop(output);
                assert!(matches!(
                    input.recv_async(&cx).await,
                    Err(TransportError::Closed)
                ));
                serving.join(&cx).await.unwrap().unwrap();
                assert_eq!(authorizations.load(Ordering::SeqCst), 4);
                assert_eq!(observations.authorized.load(Ordering::SeqCst), 1);
                assert_eq!(declaration.started.load(Ordering::SeqCst), 0);
                assert_eq!(declaration.authorized.load(Ordering::SeqCst), 0);
                upstream.close(&cx).await.unwrap();
            },
        );
        assert_eq!(retained.completed.load(Ordering::SeqCst), 1);
        assert_eq!(retained.total.load(Ordering::SeqCst), 21);
    }
    const REQUEST_EVENT: &str = "com.example/request-scaled";
    const REQUEST_OWNER: &str = "com.example/request-id";

    fn request_notification_registration(calls: Arc<AtomicUsize>) -> ExtensionRegistration {
        builder()
            .typed_request_notification::<ScaleResponse>(
                REQUEST_EVENT,
                "request-scaled-v1",
                REQUEST_OWNER,
            )
            .unwrap()
            .typed_request_sync(
                METHOD,
                "scale-params-v1",
                "scale-result-v1",
                move |context: ExtensionContext<'_, Settings>, request: ScaleRequest| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let value = request.value * context.settings().multiplier;
                    context.notify(&ScaleResponse { value })?;
                    context.notify(&ScaleResponse { value: value + 1 })?;
                    Ok(ScaleResponse { value })
                },
            )
            .unwrap()
            .build()
            .unwrap()
    }

    fn request_notification_gateway<IO>(
        upstream: fastmcp_rust::extensions::authoring::ExtensionWebSocketUpstream<IO>,
    ) -> ExtensionRegistration
    where
        IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin + Send + 'static,
    {
        builder()
            .typed_request_notification::<ScaleResponse>(
                REQUEST_EVENT,
                "request-scaled-v1",
                REQUEST_OWNER,
            )
            .unwrap()
            .typed_websocket_proxy_request_with_notifications::<
                ScaleRequest,
                ScaleResponse,
                ScaleResponse,
                IO,
            >(
                METHOD,
                "scale-params-v1",
                "scale-result-v1",
                upstream,
            )
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn typed_websocket_proxy_recorrelates_request_notifications_and_preserves_order() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        with_upstream(
            request_notification_registration(calls),
            move |cx, address| async move {
                let declarations = Arc::new(AtomicUsize::new(0));
                let transport = fastmcp_rust::AsyncWsClientTransport::connect(
                    &cx,
                    &format!("ws://{address}/mcp"),
                )
                .await
                .unwrap();
                let upstream = modern::ClientBuilder::new()
                    .connect_extension_websocket_upstream_with_cx(
                        &cx,
                        transport,
                        request_notification_registration(Arc::clone(&declarations)),
                        &ClientSettings { version: 1 },
                    )
                    .await
                    .unwrap();
                assert!(
                    builder()
                        .typed_request_notification::<ScaleResponse>(
                            REQUEST_EVENT,
                            "request-scaled-v1",
                            REQUEST_OWNER,
                        )
                        .unwrap()
                        .typed_websocket_proxy_request::<ScaleRequest, ScaleResponse, _>(
                            METHOD,
                            "scale-params-v1",
                            "scale-result-v1",
                            upstream.clone(),
                        )
                        .is_err(),
                    "notifications require the explicit notification-aware forwarding route"
                );

                let server = modern::ServerBuilder::new("typed-websocket-event-gateway", "1")
                    .extension(request_notification_gateway(upstream.clone()))
                    .unwrap()
                    .try_build()
                    .unwrap();
                let (mut peer, transport) = create_memory_transport_pair_with_capacity(8);
                let mut serving = cx
                    .spawn(move |server_cx| async move {
                        server.serve_memory(&server_cx, transport).await
                    })
                    .unwrap();
                for (id, value) in [(900, 7), (901, 9)] {
                    peer.send_async(&cx, &request(id, Some(json!({"version": 1})), json!(value)))
                        .await
                        .unwrap();
                }

                let mut events = std::collections::BTreeMap::<i64, Vec<u64>>::new();
                let mut results = std::collections::BTreeMap::new();
                for _ in 0..6 {
                    match peer.recv_async(&cx).await.unwrap() {
                        JsonRpcMessage::Request(notification) => {
                            assert!(notification.id.is_none());
                            assert_eq!(notification.method, REQUEST_EVENT);
                            let parameters = notification.params.unwrap();
                            let owner = parameters["_meta"][REQUEST_OWNER].as_i64().unwrap();
                            assert!(
                                matches!(owner, 900 | 901),
                                "the upstream request ID must not escape the gateway"
                            );
                            assert!(
                                !results.contains_key(&owner),
                                "a request cannot publish after its terminal response"
                            );
                            assert_eq!(parameters["_meta"], json!({REQUEST_OWNER: owner}));
                            events
                                .entry(owner)
                                .or_default()
                                .push(parameters["value"].as_u64().unwrap());
                        }
                        JsonRpcMessage::Response(response) => {
                            assert!(response.error.is_none(), "{response:?}");
                            let Some(RequestId::Number(owner)) = response.id else {
                                panic!("the downstream numeric request owner is retained");
                            };
                            let value = response.result.unwrap()["value"].as_u64().unwrap();
                            assert_eq!(events.get(&owner), Some(&vec![value, value + 1]));
                            assert!(results.insert(owner, value).is_none());
                        }
                    }
                }
                assert_eq!(
                    results,
                    std::collections::BTreeMap::from([(900, 21), (901, 27)])
                );
                assert_eq!(observed.load(Ordering::SeqCst), 2);
                assert_eq!(declarations.load(Ordering::SeqCst), 0);

                let (mut input, output) = peer.into_split();
                drop(output);
                assert!(matches!(
                    input.recv_async(&cx).await,
                    Err(TransportError::Closed)
                ));
                serving.join(&cx).await.unwrap().unwrap();
                upstream.close(&cx).await.unwrap();
            },
        );
    }

    #[test]
    fn typed_websocket_proxy_rejects_invalid_notification_payload_before_downstream_emission() {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(10), async {
                let (client_io, peer_io) = asupersync::net::tcp::VirtualTcpStream::pair(
                    "127.0.0.1:46201".parse().unwrap(),
                    "127.0.0.1:46202".parse().unwrap(),
                );
                let mut upstream_peer =
                    fastmcp_rust::AsyncWsServerTransport::from_upgraded(peer_io);
                let mut scripted = cx
                    .spawn(move |peer_cx| async move {
                        let JsonRpcMessage::Request(discovery) =
                            upstream_peer.recv(&peer_cx).await.unwrap()
                        else {
                            panic!("the native client discovers before forwarding");
                        };
                        assert_eq!(discovery.method, "server/discover");
                        upstream_peer
                            .send(
                                &peer_cx,
                                &JsonRpcMessage::Response(JsonRpcResponse::success(
                                    discovery.id.unwrap(),
                                    json!({
                                        "resultType": "complete",
                                        "supportedVersions": ["2026-07-28"],
                                        "capabilities": {
                                            "extensions": {
                                                (EXTENSION): {"version": 1, "multiplier": 3}
                                            }
                                        },
                                        "ttlMs": 0,
                                        "cacheScope": "private"
                                    }),
                                )),
                            )
                            .await
                            .unwrap();
                        for malformed in [true, false] {
                            let invocation = loop {
                                let JsonRpcMessage::Request(request) =
                                    upstream_peer.recv(&peer_cx).await.unwrap()
                                else {
                                    panic!("the upstream expects a forwarded request");
                                };
                                if request.method == "notifications/cancelled" {
                                    assert!(request.id.is_none());
                                    continue;
                                }
                                assert_eq!(request.method, METHOD);
                                break request;
                            };
                            let id = invocation.id.unwrap();
                            let value = invocation.params.unwrap()["value"].as_u64().unwrap() * 3;
                            let payload = if malformed {
                                json!("peer-private-invalid-value")
                            } else {
                                json!(value)
                            };
                            upstream_peer
                                .send(
                                    &peer_cx,
                                    &JsonRpcMessage::Request(JsonRpcRequest::notification(
                                        REQUEST_EVENT,
                                        Some(json!({
                                            "value": payload,
                                            "_meta": {
                                                REQUEST_OWNER: id,
                                                "com.example/upstream-only": "peer-private-metadata"
                                            }
                                        })),
                                    )),
                                )
                                .await
                                .unwrap();
                            upstream_peer
                                .send(
                                    &peer_cx,
                                    &JsonRpcMessage::Response(JsonRpcResponse::success(
                                        id,
                                        json!({"value": value}),
                                    )),
                                )
                                .await
                                .unwrap();
                        }
                        assert!(matches!(
                            upstream_peer.recv(&peer_cx).await,
                            Err(TransportError::Closed)
                        ));
                    })
                    .unwrap();
                let declaration_calls = Arc::new(AtomicUsize::new(0));
                let upstream = modern::ClientBuilder::new()
                    .connect_extension_websocket_upstream_with_cx(
                        &cx,
                        fastmcp_rust::AsyncWsClientTransport::from_upgraded(client_io),
                        request_notification_registration(Arc::clone(&declaration_calls)),
                        &ClientSettings { version: 1 },
                    )
                    .await
                    .unwrap();
                let server = modern::ServerBuilder::new("typed-websocket-rejection-gateway", "1")
                    .extension(request_notification_gateway(upstream.clone()))
                    .unwrap()
                    .try_build()
                    .unwrap();
                let (mut peer, transport) = create_memory_transport_pair_with_capacity(4);
                let mut serving = cx
                    .spawn(move |server_cx| async move {
                        server.serve_memory(&server_cx, transport).await
                    })
                    .unwrap();

                peer.send_async(&cx, &request(950, Some(json!({"version": 1})), json!(7)))
                    .await
                    .unwrap();
                let rejected = response(&cx, &mut peer, 950).await;
                assert!(rejected.result.is_none());
                let error = rejected
                    .error
                    .expect("the notification schema rejects this payload");
                assert!(!error.message.contains("peer-private"));
                assert!(
                    !fastmcp_rust::serde_json::to_string(&error)
                        .unwrap()
                        .contains("peer-private"),
                    "neither upstream payload nor metadata belongs in downstream diagnostics"
                );

                peer.send_async(&cx, &request(951, Some(json!({"version": 1})), json!(9)))
                    .await
                    .unwrap();
                let JsonRpcMessage::Request(notification) = peer.recv_async(&cx).await.unwrap()
                else {
                    panic!("a valid sibling notification still crosses the reused connection");
                };
                assert!(notification.id.is_none());
                assert_eq!(notification.method, REQUEST_EVENT);
                assert_eq!(
                    notification.params.unwrap(),
                    json!({"value": 27, "_meta": {REQUEST_OWNER: 951}})
                );
                let completed = response(&cx, &mut peer, 951).await;
                assert!(completed.error.is_none(), "{completed:?}");
                assert_eq!(completed.result.unwrap(), json!({"value": 27}));
                assert_eq!(declaration_calls.load(Ordering::SeqCst), 0);

                let (mut input, output) = peer.into_split();
                drop(output);
                assert!(matches!(
                    input.recv_async(&cx).await,
                    Err(TransportError::Closed)
                ));
                serving.join(&cx).await.unwrap().unwrap();
                upstream.close(&cx).await.unwrap();
                scripted.join(&cx).await.unwrap();
                assert!(cx.checkpoint().is_ok());
            })
            .await
            .expect("malformed notification retirement and sibling reuse are bounded");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    struct RequestNotificationDrop<'a> {
        context: ExtensionContext<'a, Settings>,
        dropped: Arc<AtomicUsize>,
        late_refused: Arc<AtomicUsize>,
    }

    impl Drop for RequestNotificationDrop<'_> {
        fn drop(&mut self) {
            if self.context.notify(&ScaleResponse { value: 999 }).is_err() {
                self.late_refused.fetch_add(1, Ordering::SeqCst);
            }
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PendingNotifyingScale {
        dropped: Arc<AtomicUsize>,
        late_refused: Arc<AtomicUsize>,
    }

    impl
        fastmcp_rust::extensions::authoring::ExtensionHandler<ScaleRequest, ScaleResponse, Settings>
        for PendingNotifyingScale
    {
        fn handle<'a>(
            &'a self,
            context: ExtensionContext<'a, Settings>,
            request: ScaleRequest,
        ) -> fastmcp_rust::BoxFuture<'a, McpResult<ScaleResponse>> {
            Box::pin(async move {
                let value = request.value * context.settings().multiplier;
                context.notify(&ScaleResponse { value })?;
                if request.value == 7 {
                    let _guard = RequestNotificationDrop {
                        context,
                        dropped: Arc::clone(&self.dropped),
                        late_refused: Arc::clone(&self.late_refused),
                    };
                    std::future::pending::<()>().await;
                }
                Ok(ScaleResponse { value })
            })
        }
    }

    #[test]
    fn typed_websocket_proxy_request_notification_cancellation_keeps_sibling_usable() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let late_refused = Arc::new(AtomicUsize::new(0));
        let observed_dropped = Arc::clone(&dropped);
        let observed_refused = Arc::clone(&late_refused);
        let producer = builder()
            .typed_request_notification::<ScaleResponse>(
                REQUEST_EVENT,
                "request-scaled-v1",
                REQUEST_OWNER,
            )
            .unwrap()
            .typed_request(
                METHOD,
                "scale-params-v1",
                "scale-result-v1",
                PendingNotifyingScale {
                    dropped,
                    late_refused,
                },
            )
            .unwrap()
            .build()
            .unwrap();
        with_upstream(producer, move |cx, address| async move {
            let transport =
                fastmcp_rust::AsyncWsClientTransport::connect(&cx, &format!("ws://{address}/mcp"))
                    .await
                    .unwrap();
            let upstream = modern::ClientBuilder::new()
                .connect_extension_websocket_upstream_with_cx(
                    &cx,
                    transport,
                    request_notification_registration(Arc::new(AtomicUsize::new(0))),
                    &ClientSettings { version: 1 },
                )
                .await
                .unwrap();
            let server = modern::ServerBuilder::new("typed-websocket-cancel-event-gateway", "1")
                .extension(request_notification_gateway(upstream.clone()))
                .unwrap()
                .try_build()
                .unwrap();
            let (mut peer, transport) = create_memory_transport_pair_with_capacity(4);
            let mut serving =
                cx.spawn(move |server_cx| async move {
                    server.serve_memory(&server_cx, transport).await
                })
                .unwrap();

            peer.send_async(&cx, &request(970, Some(json!({"version": 1})), json!(7)))
                .await
                .unwrap();
            let JsonRpcMessage::Request(first) = peer.recv_async(&cx).await.unwrap() else {
                panic!("the pending request must publish before cancellation");
            };
            assert!(first.id.is_none());
            assert_eq!(first.method, REQUEST_EVENT);
            assert_eq!(
                first.params.unwrap(),
                json!({"value": 21, "_meta": {REQUEST_OWNER: 970}})
            );
            peer.send_async(
                &cx,
                &JsonRpcMessage::Request(JsonRpcRequest::notification(
                    "notifications/cancelled",
                    Some(json!({"requestId": 970})),
                )),
            )
            .await
            .unwrap();
            peer.send_async(&cx, &request(971, Some(json!({"version": 1})), json!(9)))
                .await
                .unwrap();

            let mut sibling_events = 0;
            loop {
                match peer.recv_async(&cx).await.unwrap() {
                    JsonRpcMessage::Request(notification) => {
                        assert!(notification.id.is_none());
                        assert_eq!(notification.method, REQUEST_EVENT);
                        assert_eq!(
                            notification.params.unwrap(),
                            json!({"value": 27, "_meta": {REQUEST_OWNER: 971}}),
                            "the cancelled owner cannot publish into a sibling execution"
                        );
                        sibling_events += 1;
                        assert_eq!(sibling_events, 1);
                    }
                    JsonRpcMessage::Response(response) => match response.id {
                        Some(RequestId::Number(970)) => {
                            assert!(response.result.is_none());
                            assert!(response.error.is_some());
                        }
                        Some(RequestId::Number(971)) => {
                            assert!(response.error.is_none(), "{response:?}");
                            assert_eq!(response.result.unwrap(), json!({"value": 27}));
                            assert_eq!(sibling_events, 1);
                            break;
                        }
                        _ => panic!("unexpected downstream response owner"),
                    },
                }
            }
            while observed_dropped.load(Ordering::SeqCst) == 0 {
                asupersync::runtime::yield_now().await;
            }
            assert_eq!(observed_dropped.load(Ordering::SeqCst), 1);
            assert_eq!(observed_refused.load(Ordering::SeqCst), 1);
            assert!(cx.checkpoint().is_ok());

            let (mut input, output) = peer.into_split();
            drop(output);
            assert!(matches!(
                input.recv_async(&cx).await,
                Err(TransportError::Closed)
            ));
            serving.join(&cx).await.unwrap().unwrap();
            upstream.close(&cx).await.unwrap();
        });
    }
}

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::runtime::RuntimeBuilder;
use fastmcp_rust::extensions::authoring::{
    ExtensionBuilder, ExtensionContext, ExtensionNotificationContext, ExtensionNotificationHandler,
    ExtensionRegistration,
};
use fastmcp_rust::memory::{MemoryTransport, create_memory_transport_pair_with_capacity};
use fastmcp_rust::serde::{Deserialize, Serialize};
use fastmcp_rust::{
    Cx, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, JsonSchema, McpError, McpResult,
    RequestId, TransportError, extension, json, modern,
};

const EXTENSION: &str = "com.example/typed-math";
const METHOD: &str = "com.example/scale";

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ClientSettings {
    version: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ServerSettings {
    version: u32,
    multiplier: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct Settings {
    multiplier: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ScaleRequest {
    value: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ScaleResponse {
    value: u32,
}

fn builder() -> ExtensionBuilder<ClientSettings, ServerSettings, Settings> {
    ExtensionBuilder::new(
        EXTENSION,
        1,
        "typed-math-client-v1",
        "typed-math-server-v1",
        ServerSettings {
            version: 1,
            multiplier: 3,
        },
        |client: ClientSettings, server: ServerSettings| {
            if client.version != server.version {
                return Err(McpError::invalid_params("incompatible math version"));
            }
            Ok(Settings {
                multiplier: server.multiplier,
            })
        },
    )
    .expect("admitted typed settings")
}

fn registration(calls: Arc<AtomicUsize>) -> ExtensionRegistration {
    builder()
        .typed_request_sync(
            METHOD,
            "scale-params-v1",
            "scale-result-v1",
            move |context: ExtensionContext<'_, Settings>, request: ScaleRequest| {
                context.checkpoint()?;
                assert_eq!(context.descriptor().id(), EXTENSION);
                assert_eq!(context.descriptor().version(), 1);
                assert_eq!(context.method(), METHOD);
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(ScaleResponse {
                    value: request.value * context.settings().multiplier,
                })
            },
        )
        .expect("typed method installs")
        .build()
        .expect("sealed registration")
}

#[extension(
    method = "com.example/scale",
    params_schema = "scale-params-v1",
    result_schema = "scale-result-v1"
)]
async fn scale(
    context: ExtensionContext<'_, Settings>,
    request: ScaleRequest,
) -> McpResult<ScaleResponse> {
    // Yield on the caller's executor without obtaining or constructing a Cx.
    let mut yielded = false;
    std::future::poll_fn(|task| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            task.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await;
    context.checkpoint()?;
    Ok(ScaleResponse {
        value: request.value * context.settings().multiplier,
    })
}

fn request(
    id: i64,
    settings: Option<fastmcp_rust::JsonValue>,
    value: fastmcp_rust::JsonValue,
) -> JsonRpcMessage {
    // Advertise Tasks in the shared baseline so each negative below isolates
    // the typed extension's settings or schema. The composition test explicitly
    // removes Tasks to exercise its per-request inactivity, and corrupts its
    // settings separately to verify the frozen bilateral validator still runs.
    let mut capabilities = json!({
        "extensions": {"io.modelcontextprotocol/tasks": {}}
    });
    if let Some(settings) = settings {
        capabilities["extensions"][EXTENSION] = settings;
    }
    JsonRpcMessage::Request(JsonRpcRequest::new(
        METHOD,
        Some(json!({
            "value": value,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": capabilities
            }
        })),
        id,
    ))
}

async fn response(cx: &Cx, peer: &mut MemoryTransport, id: i64) -> JsonRpcResponse {
    let JsonRpcMessage::Response(response) = peer.recv_async(cx).await.expect("server response")
    else {
        panic!("extension request must return a response");
    };
    assert_eq!(response.id, Some(RequestId::Number(id)));
    response
}

fn run_exchange(
    registration: ExtensionRegistration,
    requests: Vec<JsonRpcMessage>,
) -> Vec<JsonRpcResponse> {
    let server = modern::ServerBuilder::new("typed-extension", "1.0")
        .extension(registration)
        .expect("installation before freeze")
        .try_build()
        .expect("immutable server");
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .expect("application-owned runtime");
    let responses = runtime.block_on(async move {
        let cx = Cx::current().expect("caller context");
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let (mut peer, transport) = create_memory_transport_pair_with_capacity(1);
            let mut serving = cx
                .spawn(move |cx| async move { server.serve_memory(&cx, transport).await })
                .expect("owned server task");
            let mut responses = Vec::new();
            for (index, request) in requests.iter().enumerate() {
                peer.send_async(&cx, request)
                    .await
                    .expect("request admitted");
                responses.push(response(&cx, &mut peer, index as i64 + 1).await);
            }
            let (mut input, output) = peer.into_split();
            drop(output);
            assert!(matches!(
                input.recv_async(&cx).await,
                Err(TransportError::Closed)
            ));
            serving
                .join(&cx)
                .await
                .expect("server task settled")
                .expect("server closed");
            responses
        })
        .await
        .expect("bounded exchange and cleanup")
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    responses
}

#[test]
fn typed_extension_settings_and_schema_are_enforced_per_request() {
    let calls = Arc::new(AtomicUsize::new(0));
    let registration = registration(Arc::clone(&calls));
    assert_eq!(registration.descriptor().id(), EXTENSION);
    assert_eq!(registration.descriptor().version(), 1);
    let responses = run_exchange(
        registration,
        vec![
            request(1, Some(json!({"version": 1})), json!(7)),
            request(2, None, json!(7)),
            request(3, Some(json!({"version": 2})), json!(7)),
            request(4, Some(json!({"version": "bad"})), json!(7)),
            request(5, Some(json!({"version": 1})), json!("bad")),
            request(6, Some(json!({"version": 1})), json!(11)),
        ],
    );
    assert!(responses[0].error.is_none(), "{:?}", responses[0]);
    assert_eq!(responses[0].result.as_ref().unwrap()["value"], 21);
    for response in &responses[1..5] {
        assert!(
            response.error.is_some(),
            "rejected request had a successful result: {response:?}"
        );
        assert!(response.result.is_none());
    }
    assert!(responses[5].error.is_none(), "{:?}", responses[5]);
    assert_eq!(responses[5].result.as_ref().unwrap()["value"], 33);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "only admitted requests run handlers"
    );
}

#[test]
fn attribute_extension_yields_on_caller_runtime_and_returns_typed_result() {
    let registration = ScaleExtension
        .register(builder())
        .expect("attribute-generated registration")
        .build()
        .unwrap();
    let responses = run_exchange(
        registration,
        vec![
            request(1, Some(json!({"version": 1})), json!(9)),
            request(2, Some(json!({"version": 2})), json!(9)),
        ],
    );
    assert!(responses[0].error.is_none(), "{:?}", responses[0]);
    assert_eq!(responses[0].result.as_ref().unwrap()["value"], 27);
    assert!(responses[1].error.is_some());
}

#[test]
#[cfg(feature = "tasks")]
fn typed_extension_requests_compose_with_optional_default_tasks() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut requests = vec![
        request(1, Some(json!({"version": 1})), json!(7)),
        request(2, Some(json!({"version": 1})), json!(11)),
        request(3, Some(json!({"version": 1})), json!(13)),
        request(4, None, json!(13)),
        request(5, Some(json!({"version": 1})), json!(17)),
    ];
    for (index, settings) in [
        (0, None),
        (1, Some(json!({}))),
        (2, Some(json!({"unexpected": true}))),
        (3, Some(json!({}))),
        (4, None),
    ] {
        let JsonRpcMessage::Request(request) = &mut requests[index] else {
            panic!("fixture is an extension request");
        };
        let extensions =
            request.params.as_mut().unwrap()["_meta"]["io.modelcontextprotocol/clientCapabilities"]
                ["extensions"]
                .as_object_mut()
                .unwrap();
        match settings {
            Some(settings) => {
                extensions.insert("io.modelcontextprotocol/tasks".to_owned(), settings);
            }
            None => {
                extensions.remove("io.modelcontextprotocol/tasks");
            }
        }
    }
    let responses = run_exchange(registration(Arc::clone(&calls)), requests);
    for (index, expected) in [(0, 21), (1, 33), (4, 51)] {
        assert!(responses[index].error.is_none(), "{:?}", responses[index]);
        assert_eq!(responses[index].result.as_ref().unwrap()["value"], expected);
    }
    for response in &responses[2..4] {
        assert!(response.error.is_some(), "{response:?}");
        assert!(response.result.is_none());
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "absent Tasks is optional; malformed Tasks and absent typed settings cannot reach the handler",
    );
}

#[test]
fn sealed_extension_installation_preserves_existing_registration() {
    let first = registration(Arc::new(AtomicUsize::new(0)));
    let second = registration(Arc::new(AtomicUsize::new(0)));
    let builder = modern::ServerBuilder::new("typed-extension", "1.0")
        .extension(first)
        .unwrap();
    assert!(
        builder.extension(second).is_err(),
        "installation cannot silently replace a registry"
    );
}

mod composition {
    use super::*;
    use std::collections::BTreeMap;

    use fastmcp_rust::{
        ClientExtensionDiscovery, ExtensionDescriptor, ExtensionDescriptorRegistry,
        ExtensionDirection, ExtensionFallbackPolicy, ExtensionHttpEraDisposition, ExtensionId,
        ExtensionMethodDescriptor, ExtensionNegotiationError, ExtensionNegotiationResolver,
        ExtensionNotificationDescriptor, ExtensionSettings, ExtensionSettingsSchema,
        ModernHttpExtensionEvent, SseLimits,
    };

    const OFFSET_EXTENSION: &str = "com.example/typed-offset";
    const OFFSET_METHOD: &str = "com.example/offset";
    const SCALE_EVENT: &str = "com.example/composed-scale";
    const OFFSET_EVENT: &str = "com.example/composed-offset";
    const SCALE_OWNER: &str = "com.example/scale-request";
    const OFFSET_OWNER: &str = "com.example/offset-request";

    #[derive(Deserialize, Serialize, JsonSchema)]
    #[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
    struct OffsetClientSettings {
        revision: u32,
    }

    #[derive(Deserialize, Serialize, JsonSchema)]
    #[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
    struct OffsetServerSettings {
        revision: u32,
        increment: u32,
    }

    #[derive(Deserialize, Serialize, JsonSchema)]
    #[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
    struct OffsetSettings {
        increment: u32,
    }

    #[derive(Deserialize, Serialize, JsonSchema)]
    #[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
    struct OffsetNotice {
        label: String,
    }

    fn registrations(
        calls: &Arc<[AtomicUsize; 2]>,
    ) -> (ExtensionRegistration, ExtensionRegistration) {
        let scale_calls = Arc::clone(calls);
        let scale = builder()
            .typed_request_notification::<ScaleResponse>(
                SCALE_EVENT,
                "composition-scale-notice-v1",
                SCALE_OWNER,
            )
            .unwrap()
            .typed_request_sync(
                METHOD,
                "scale-params-v1",
                "scale-result-v1",
                move |context: ExtensionContext<'_, Settings>, request: ScaleRequest| {
                    context.checkpoint()?;
                    assert_eq!(context.descriptor().id(), EXTENSION);
                    assert_eq!(context.settings().multiplier, 3);
                    scale_calls[0].fetch_add(1, Ordering::SeqCst);
                    let value = request.value * context.settings().multiplier;
                    context.notify(&ScaleResponse { value })?;
                    Ok(ScaleResponse { value })
                },
            )
            .unwrap()
            .build()
            .unwrap();
        let offset_calls = Arc::clone(calls);
        let offset = ExtensionBuilder::new(
            OFFSET_EXTENSION,
            1,
            "composition-offset-client-v1",
            "composition-offset-server-v1",
            OffsetServerSettings {
                revision: 2,
                increment: 7,
            },
            |client: OffsetClientSettings, server: OffsetServerSettings| {
                if client.revision != server.revision {
                    return Err(McpError::invalid_params("incompatible offset revision"));
                }
                Ok(OffsetSettings {
                    increment: server.increment,
                })
            },
        )
        .unwrap()
        .typed_request_notification::<OffsetNotice>(
            OFFSET_EVENT,
            "composition-offset-notice-v1",
            OFFSET_OWNER,
        )
        .unwrap()
        .typed_request_sync(
            OFFSET_METHOD,
            "composition-offset-params-v1",
            "composition-offset-result-v1",
            move |context: ExtensionContext<'_, OffsetSettings>, request: ScaleRequest| {
                context.checkpoint()?;
                assert_eq!(context.descriptor().id(), OFFSET_EXTENSION);
                assert_eq!(context.settings().increment, 7);
                offset_calls[1].fetch_add(1, Ordering::SeqCst);
                let value = request.value + context.settings().increment;
                if request.value == 13 {
                    // Valid for the other extension, invalid for this owner.
                    context.notify(&ScaleResponse { value })?;
                } else {
                    context.notify(&OffsetNotice {
                        label: format!("offset:{value}"),
                    })?;
                }
                Ok(ScaleResponse { value })
            },
        )
        .unwrap()
        .build()
        .unwrap();
        (scale, offset)
    }

    fn server(calls: &Arc<[AtomicUsize; 2]>, reverse: bool) -> modern::Server {
        let (scale, offset) = registrations(calls);
        let server = modern::ServerBuilder::new("composed-typed-extensions", "1");
        #[cfg(feature = "apps")]
        let server = if reverse {
            server.mcp_apps().unwrap()
        } else {
            server
        };
        let server = if reverse {
            server.extension(offset).unwrap().extension(scale).unwrap()
        } else {
            server.extension(scale).unwrap().extension(offset).unwrap()
        };
        #[cfg(feature = "apps")]
        let server = if reverse {
            server
        } else {
            server.mcp_apps().unwrap()
        };
        server.try_build().unwrap()
    }

    fn message(
        id: i64,
        method: &str,
        scale: Option<fastmcp_rust::JsonValue>,
        offset: Option<fastmcp_rust::JsonValue>,
        value: fastmcp_rust::JsonValue,
    ) -> JsonRpcMessage {
        let mut extensions = json!({});
        if let Some(settings) = scale {
            extensions[EXTENSION] = settings;
        }
        if let Some(settings) = offset {
            extensions[OFFSET_EXTENSION] = settings;
        }
        let mut parameters = json!({"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": extensions
            }
        }});
        if method != "server/discover" {
            parameters["value"] = value;
        }
        JsonRpcMessage::Request(JsonRpcRequest::new(method, Some(parameters), id))
    }

    #[test]
    fn typed_extensions_compose_on_memory_with_isolated_settings_and_notifications() {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
                for reverse in [false, true] {
                    let calls = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
                    let server = server(&calls, reverse);
                    let (mut peer, transport) = create_memory_transport_pair_with_capacity(1);
                    let mut serving = cx
                        .spawn(move |server_cx| async move {
                            server.serve_memory(&server_cx, transport).await
                        })
                        .unwrap();
                    peer.send_async(
                        &cx,
                        &message(
                            0,
                            "server/discover",
                            Some(json!({"version": 1})),
                            Some(json!({"revision": 2})),
                            json!(null),
                        ),
                    )
                    .await
                    .unwrap();
                    let discovery = response(&cx, &mut peer, 0).await;
                    assert!(discovery.error.is_none(), "{discovery:?}");
                    let advertised =
                        &discovery.result.as_ref().unwrap()["capabilities"]["extensions"];
                    assert_eq!(
                        advertised[EXTENSION],
                        json!({"version": 1, "multiplier": 3})
                    );
                    assert_eq!(
                        advertised[OFFSET_EXTENSION],
                        json!({"revision": 2, "increment": 7})
                    );
                    #[cfg(feature = "apps")]
                    assert_eq!(advertised["io.modelcontextprotocol/ui"], json!({}));
                    #[cfg(feature = "tasks")]
                    assert_eq!(advertised["io.modelcontextprotocol/tasks"], json!({}));

                    let cases = [
                        (
                            METHOD,
                            Some(json!({"version": 1})),
                            Some(json!({"revision": 2})),
                            json!(7),
                            Some(21),
                        ),
                        (
                            OFFSET_METHOD,
                            Some(json!({"version": 1})),
                            Some(json!({"revision": 2})),
                            json!(7),
                            Some(14),
                        ),
                        (METHOD, None, Some(json!({"revision": 2})), json!(7), None),
                        (
                            OFFSET_METHOD,
                            Some(json!({"version": 1})),
                            None,
                            json!(7),
                            None,
                        ),
                        (
                            METHOD,
                            Some(json!({"version": 1})),
                            Some(json!({"version": 1})),
                            json!(7),
                            None,
                        ),
                        (
                            OFFSET_METHOD,
                            Some(json!({"version": 1})),
                            Some(json!({"revision": 2})),
                            json!("bad"),
                            None,
                        ),
                        (
                            OFFSET_METHOD,
                            Some(json!({"version": 1})),
                            Some(json!({"revision": 2})),
                            json!(13),
                            None,
                        ),
                        (
                            METHOD,
                            Some(json!({"version": 1})),
                            Some(json!({"revision": 2})),
                            json!(11),
                            Some(33),
                        ),
                        (
                            OFFSET_METHOD,
                            Some(json!({"version": 1})),
                            Some(json!({"revision": 2})),
                            json!(11),
                            Some(18),
                        ),
                    ];
                    for (index, (method, scale, offset, value, expected)) in
                        cases.into_iter().enumerate()
                    {
                        let id = i64::try_from(index).unwrap() + 1;
                        peer.send_async(&cx, &message(id, method, scale, offset, value))
                            .await
                            .unwrap();
                        if let Some(value) = expected {
                            let JsonRpcMessage::Request(notice) =
                                peer.recv_async(&cx).await.unwrap()
                            else {
                                panic!("each composed handler emits its own notification first");
                            };
                            assert!(notice.id.is_none());
                            let (event, owner, other_owner, application) = if method == METHOD {
                                (
                                    SCALE_EVENT,
                                    SCALE_OWNER,
                                    OFFSET_OWNER,
                                    json!({"value": value}),
                                )
                            } else {
                                (
                                    OFFSET_EVENT,
                                    OFFSET_OWNER,
                                    SCALE_OWNER,
                                    json!({"label": format!("offset:{value}")}),
                                )
                            };
                            assert_eq!(notice.method, event);
                            let mut parameters = notice.params.unwrap();
                            let metadata =
                                parameters.as_object_mut().unwrap().remove("_meta").unwrap();
                            assert_eq!(metadata[owner], json!(id));
                            assert!(metadata.get(other_owner).is_none());
                            assert_eq!(parameters, application);
                            let terminal = response(&cx, &mut peer, id).await;
                            assert!(terminal.error.is_none(), "{terminal:?}");
                            assert_eq!(terminal.result.as_ref().unwrap()["value"], value);
                        } else {
                            let terminal = response(&cx, &mut peer, id).await;
                            assert!(terminal.error.is_some(), "{terminal:?}");
                            assert!(terminal.result.is_none());
                        }
                    }
                    assert_eq!(calls[0].load(Ordering::SeqCst), 2);
                    assert_eq!(calls[1].load(Ordering::SeqCst), 3);
                    assert!(cx.checkpoint().is_ok());
                    let (mut input, output) = peer.into_split();
                    drop(output);
                    assert!(matches!(
                        input.recv_async(&cx).await,
                        Err(TransportError::Closed)
                    ));
                    serving.join(&cx).await.unwrap().unwrap();
                }
            })
            .await
            .expect("composed requests, rejection and shutdown remain bounded");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    fn http_consumer() -> (ExtensionDescriptorRegistry, ClientExtensionDiscovery) {
        let mut registry = ExtensionDescriptorRegistry::new();
        for (id, method, event, client_schema, server_schema) in [
            (
                EXTENSION,
                METHOD,
                SCALE_EVENT,
                "typed-math-client-v1",
                "typed-math-server-v1",
            ),
            (
                OFFSET_EXTENSION,
                OFFSET_METHOD,
                OFFSET_EVENT,
                "composition-offset-client-v1",
                "composition-offset-server-v1",
            ),
        ] {
            registry
                .register(ExtensionDescriptor {
                    id: ExtensionId::parse(id).unwrap(),
                    client_settings: ExtensionSettingsSchema {
                        schema_id: client_schema.into(),
                        codec_id: "client-codec-v1".into(),
                    },
                    server_settings: ExtensionSettingsSchema {
                        schema_id: server_schema.into(),
                        codec_id: "server-codec-v1".into(),
                    },
                    resolver: ExtensionNegotiationResolver {
                        id: "composition-client-resolver-v1".into(),
                        version: 1,
                        fallback: ExtensionFallbackPolicy::RejectOneSided,
                    },
                    method: Some(ExtensionMethodDescriptor {
                        name: method.into(),
                        direction: ExtensionDirection::ClientToServer,
                        http_era_disposition: Some(ExtensionHttpEraDisposition::ModernExclusive),
                        legacy_fallback: false,
                    }),
                    notification: Some(ExtensionNotificationDescriptor {
                        name: event.into(),
                        direction: ExtensionDirection::ServerToClient,
                        activation_proof: None,
                    }),
                    result_discriminator: None,
                    routing_headers: vec![],
                    stdio_correlation: None,
                })
                .unwrap();
        }
        let discovery = ClientExtensionDiscovery {
            extensions: BTreeMap::from([
                (
                    ExtensionId::parse(EXTENSION).unwrap(),
                    ExtensionSettings::new(json!({"version": 1})).unwrap(),
                ),
                (
                    ExtensionId::parse(OFFSET_EXTENSION).unwrap(),
                    ExtensionSettings::new(json!({"revision": 2})).unwrap(),
                ),
            ]),
        };
        (registry, discovery)
    }

    fn compatible(
        descriptor: &ExtensionDescriptor,
        client: &ExtensionSettings,
        server: &ExtensionSettings,
    ) -> Result<ExtensionSettings, ExtensionNegotiationError> {
        let key = if descriptor.id.as_str() == EXTENSION {
            "version"
        } else if descriptor.id.as_str() == OFFSET_EXTENSION {
            "revision"
        } else {
            return Err(ExtensionNegotiationError::SettingsCompatibilityRejected(
                descriptor.id.to_string(),
            ));
        };
        if client.as_object().get(key) != server.as_object().get(key) {
            return Err(ExtensionNegotiationError::SettingsCompatibilityRejected(
                descriptor.id.to_string(),
            ));
        }
        Ok(server.clone())
    }

    #[test]
    fn typed_extensions_compose_on_native_http_with_separate_notification_schemas() {
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        let calls = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let observed = Arc::clone(&calls);
        runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
                let server = server(&calls, false);
                let bound = server.bind_http(&cx, "127.0.0.1:0").await.unwrap();
                let endpoint = fastmcp_rust::CanonicalHttpUrl::parse(&format!(
                    "http://{}/mcp",
                    bound.local_addr().unwrap()
                ))
                .unwrap();
                let (ready, mut receiver) = asupersync::channel::oneshot::channel();
                let mut serving = cx
                    .spawn(move |server_cx| async move {
                        ready.send(&server_cx, server_cx.clone()).unwrap();
                        bound.serve(&server_cx).await
                    })
                    .unwrap();
                let server_cx = receiver.recv(&cx).await.unwrap();
                let (registry, discovery) = http_consumer();
                let client = modern::ClientBuilder::new()
                    .extension_registry(registry, discovery, || compatible)
                    .unwrap()
                    .connect_http_with_cx(&cx, endpoint)
                    .await
                    .unwrap();
                let limits = SseLimits::new(64 * 1024, 64 * 1024, 64).unwrap();
                for (extension, method, event, expected, notification) in [
                    (EXTENSION, METHOD, SCALE_EVENT, 21, json!({"value": 21})),
                    (
                        OFFSET_EXTENSION,
                        OFFSET_METHOD,
                        OFFSET_EVENT,
                        14,
                        json!({"label": "offset:14"}),
                    ),
                ] {
                    let id = ExtensionId::parse(extension).unwrap();
                    let mut execution = client
                        .execute_final_extension(&cx, &id, method, json!({"value": 7}), limits)
                        .unwrap();
                    let Some(ModernHttpExtensionEvent::ExtensionNotification {
                        notification: received,
                        ..
                    }) = execution.next_event(&cx).await.unwrap()
                    else {
                        panic!("each extension preserves its own HTTP notification");
                    };
                    assert_eq!(received.method, event);
                    assert_eq!(received.params, Some(notification));
                    assert!(matches!(
                        execution.next_event(&cx).await.unwrap(),
                        Some(ModernHttpExtensionEvent::Terminal(result))
                            if result["value"] == expected
                    ));
                    assert!(execution.next_event(&cx).await.unwrap().is_none());
                }

                let id = ExtensionId::parse(OFFSET_EXTENSION).unwrap();
                let mut invalid = client
                    .execute_final_extension(&cx, &id, OFFSET_METHOD, json!({"value": 13}), limits)
                    .unwrap();
                assert!(
                    invalid.next_event(&cx).await.is_err(),
                    "a payload valid only for the other owner cannot be emitted"
                );
                assert!(invalid.next_event(&cx).await.unwrap().is_none());

                let id = ExtensionId::parse(EXTENSION).unwrap();
                let mut sibling = client
                    .execute_final_extension(&cx, &id, METHOD, json!({"value": 9}), limits)
                    .unwrap();
                assert!(matches!(
                    sibling.next_event(&cx).await.unwrap(),
                    Some(ModernHttpExtensionEvent::ExtensionNotification { notification, .. })
                        if notification.method == SCALE_EVENT
                            && notification.params == Some(json!({"value": 27}))
                ));
                assert!(matches!(
                    sibling.next_event(&cx).await.unwrap(),
                    Some(ModernHttpExtensionEvent::Terminal(result))
                        if result["value"] == 27
                ));
                assert!(sibling.next_event(&cx).await.unwrap().is_none());
                drop(client);
                server_cx.cancel_with(
                    asupersync::types::CancelKind::Shutdown,
                    Some("composed extension HTTP test complete"),
                );
                assert!(matches!(
                    serving.join(&cx).await.unwrap().unwrap(),
                    fastmcp_rust::HttpServerShutdown::Quiescent
                ));
            })
            .await
            .expect("composed HTTP handlers and cleanup remain bounded");
        });
        assert_eq!(observed[0].load(Ordering::SeqCst), 2);
        assert_eq!(observed[1].load(Ordering::SeqCst), 2);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn typed_extensions_reject_a_second_owner_of_the_same_method() {
        let first = registration(Arc::new(AtomicUsize::new(0)));
        let second = ExtensionBuilder::new(
            OFFSET_EXTENSION,
            1,
            "collision-client-v1",
            "collision-server-v1",
            ServerSettings {
                version: 1,
                multiplier: 5,
            },
            |client: ClientSettings, server: ServerSettings| {
                if client.version != server.version {
                    return Err(McpError::invalid_params("incompatible version"));
                }
                Ok(Settings {
                    multiplier: server.multiplier,
                })
            },
        )
        .unwrap()
        .typed_request_sync(
            METHOD,
            "scale-params-v1",
            "scale-result-v1",
            |context: ExtensionContext<'_, Settings>, request: ScaleRequest| {
                Ok(ScaleResponse {
                    value: request.value * context.settings().multiplier,
                })
            },
        )
        .unwrap()
        .build()
        .unwrap();
        assert!(
            modern::ServerBuilder::new("conflicting-extension-owner", "1")
                .extension(first)
                .unwrap()
                .extension(second)
                .is_err(),
            "composition cannot replace another extension's method"
        );
    }
}

const NOTIFICATION: &str = "com.example/scaled";
const ACTIVATION: &str = "com.example/activation";

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ScaleNotification {
    value: u32,
    hold: bool,
}

#[derive(Default)]
struct NotificationObservations {
    authorized: AtomicUsize,
    started: AtomicUsize,
    completed: AtomicUsize,
    abandoned: AtomicUsize,
    total: AtomicUsize,
}

struct NotificationGuard {
    observations: Arc<NotificationObservations>,
    completed: bool,
}

impl Drop for NotificationGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.observations.abandoned.fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct ScaleNotificationHandler(Arc<NotificationObservations>);

impl ExtensionNotificationHandler<ScaleNotification, Settings> for ScaleNotificationHandler {
    fn handle<'a>(
        &'a self,
        context: ExtensionNotificationContext<'a, Settings>,
        notification: ScaleNotification,
    ) -> fastmcp_rust::BoxFuture<'a, McpResult<()>> {
        Box::pin(async move {
            let mut guard = NotificationGuard {
                observations: Arc::clone(&self.0),
                completed: false,
            };
            self.0.started.fetch_add(1, Ordering::SeqCst);
            assert_eq!(context.descriptor().id(), EXTENSION);
            assert_eq!(context.method(), NOTIFICATION);
            assert_eq!(
                context.notification_descriptor().activation_metadata_key(),
                ACTIVATION
            );
            if notification.hold {
                std::future::pending::<()>().await;
            }
            asupersync::runtime::yield_now().await;
            context.checkpoint()?;
            self.0.total.fetch_add(
                usize::try_from(notification.value).expect("bounded fixture input")
                    * usize::try_from(context.settings().multiplier).expect("bounded multiplier"),
                Ordering::SeqCst,
            );
            self.0.completed.fetch_add(1, Ordering::SeqCst);
            guard.completed = true;
            Ok(())
        })
    }
}

fn notification_registration(observations: Arc<NotificationObservations>) -> ExtensionRegistration {
    let authorization = Arc::clone(&observations);
    builder()
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
        .expect("typed notification registers without raw descriptor authority")
        .build()
        .expect("notification-only extension seals")
}

fn notification(value: u32, hold: bool) -> fastmcp_rust::JsonValue {
    json!({
        "jsonrpc": "2.0",
        "method": NOTIFICATION,
        "params": {
            "value": value,
            "hold": hold,
            "_meta": { (ACTIVATION): { "version": 1 } }
        }
    })
}

async fn notification_http_exchange(
    address: std::net::SocketAddr,
    message: fastmcp_rust::JsonValue,
    authorization: bool,
) -> std::io::Result<Vec<u8>> {
    use asupersync::io::{AsyncReadExt, AsyncWriteExt};

    let body = fastmcp_rust::serde_json::to_vec(&message).map_err(std::io::Error::other)?;
    let authorization = if authorization {
        "Authorization: Bearer typed-notification-secret\r\n"
    } else {
        ""
    };
    let headers = format!(
        "POST /mcp HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nAccept-Encoding: identity\r\nConnection: close\r\n{authorization}Content-Length: {}\r\n\r\n",
        body.len()
    );
    let socket = asupersync::net::TcpStream::connect(address).await?;
    struct ResetOnIncompleteDrop {
        socket: asupersync::net::TcpStream,
        completed: bool,
    }
    impl Drop for ResetOnIncompleteDrop {
        fn drop(&mut self) {
            if !self.completed {
                let _ = self.socket.set_zero_linger();
            }
        }
    }
    let mut guard = ResetOnIncompleteDrop {
        socket,
        completed: false,
    };
    guard.socket.write_all(headers.as_bytes()).await?;
    guard.socket.write_all(&body).await?;
    guard.socket.flush().await?;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let count = guard.socket.read(&mut buffer).await?;
        if count == 0 {
            guard.completed = true;
            return Ok(response);
        }
        guard.completed = true;
        assert!(response.len() + count <= 64 * 1024, "bounded wire response");
        response.extend_from_slice(&buffer[..count]);
    }
}

fn with_notification_http<F, Fut>(exercise: F) -> Arc<NotificationObservations>
where
    F: FnOnce(Cx, Cx, std::net::SocketAddr, Arc<NotificationObservations>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let observations = Arc::new(NotificationObservations::default());
    let retained = Arc::clone(&observations);
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().expect("caller reactor"))
        .build()
        .expect("caller-owned HTTP runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("caller context");
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let verifier = fastmcp_rust::StaticTokenVerifier::new([(
                "typed-notification-secret",
                fastmcp_rust::AuthContext::with_subject("notification-owner"),
            )])
            .expect("bounded test credential");
            let server = modern::ServerBuilder::new("typed-notifications", "1.0")
                .extension(notification_registration(Arc::clone(&observations)))
                .expect("public facade extension installation")
                .auth_provider(fastmcp_rust::TokenAuthProvider::new(verifier))
                .try_build()
                .expect("frozen modern server");
            let bound = server
                .bind_http(&cx, "127.0.0.1:0")
                .await
                .expect("live native listener");
            let address = bound.local_addr().unwrap();
            let (sender, mut receiver) = asupersync::channel::oneshot::channel();
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    sender
                        .send(&server_cx, server_cx.clone())
                        .expect("live parent retains listener context");
                    bound.serve(&server_cx).await
                })
                .expect("owned listener task");
            let server_cx = receiver.recv(&cx).await.expect("listener owner ready");
            exercise(cx.clone(), server_cx.clone(), address, observations).await;
            server_cx.cancel_with(
                asupersync::types::CancelKind::Shutdown,
                Some("notification test complete"),
            );
            let shutdown = serving
                .join(&cx)
                .await
                .expect("owned listener joins")
                .expect("listener shutdown");
            assert!(
                matches!(shutdown, fastmcp_rust::HttpServerShutdown::Quiescent),
                "all connection children settle"
            );
        })
        .await
        .expect("bounded notification exchange and cleanup");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    retained
}

#[test]
fn typed_notification_http_completes_and_revalidates_activation() {
    let observations =
        with_notification_http(|_cx, _server_cx, address, observations| async move {
            let valid = notification(7, false);
            let unauthenticated = notification_http_exchange(address, valid.clone(), false)
                .await
                .unwrap();
            assert!(unauthenticated.starts_with(b"HTTP/1.1 401"));
            assert_eq!(
                observations.authorized.load(Ordering::SeqCst),
                0,
                "authentication precedes the extension policy"
            );
            assert_eq!(observations.started.load(Ordering::SeqCst), 0);

            let accepted = notification_http_exchange(address, valid.clone(), true)
                .await
                .unwrap();
            assert!(
                accepted.starts_with(b"HTTP/1.1 202"),
                "{}",
                String::from_utf8_lossy(&accepted)
            );
            assert!(
                accepted.ends_with(b"\r\n\r\n"),
                "notification acknowledgement has no JSON-RPC result"
            );
            assert_eq!(
                observations.completed.load(Ordering::SeqCst),
                1,
                "completion precedes HTTP acknowledgement"
            );
            assert_eq!(observations.total.load(Ordering::SeqCst), 21);

            let mut missing = valid.clone();
            missing["params"]["_meta"]
                .as_object_mut()
                .unwrap()
                .remove(ACTIVATION);
            let mut incompatible = valid.clone();
            incompatible["params"]["_meta"][ACTIVATION]["version"] = json!(2);
            let mut malformed = valid.clone();
            malformed["params"]["value"] = json!("wrong-type");
            let mut unexpected = valid.clone();
            unexpected["params"]["unexpected"] = json!(true);
            let mut request_shaped = valid.clone();
            request_shaped["id"] = json!(9);
            let mut unknown = valid.clone();
            unknown["method"] = json!("com.example/unregistered");
            for (rejected, status) in [
                (missing, 400),
                (incompatible, 400),
                (malformed, 400),
                (unexpected, 400),
                (request_shaped, 400),
                (unknown, 400),
                (notification(13, false), 403),
            ] {
                let response = notification_http_exchange(address, rejected, true)
                    .await
                    .unwrap();
                assert!(
                    response.starts_with(format!("HTTP/1.1 {status}").as_bytes()),
                    "{}",
                    String::from_utf8_lossy(&response)
                );
                assert_eq!(
                    observations.started.load(Ordering::SeqCst),
                    1,
                    "refusal precedes the handler"
                );
                assert_eq!(observations.completed.load(Ordering::SeqCst), 1);
                assert_eq!(observations.total.load(Ordering::SeqCst), 21);
            }
            let mut fresh = notification(11, false);
            fresh["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] =
                json!("2025-11-25");
            fresh["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
                json!({"extensions":{(EXTENSION):{"version":2}}});
            let accepted = notification_http_exchange(address, fresh, true)
                .await
                .unwrap();
            assert!(
                accepted.starts_with(b"HTTP/1.1 202"),
                "only the descriptor-owned proof can activate a notification"
            );
            assert_eq!(observations.total.load(Ordering::SeqCst), 54);
        });
    assert_eq!(observations.completed.load(Ordering::SeqCst), 2);
    assert_eq!(observations.abandoned.load(Ordering::SeqCst), 0);
}

#[test]
fn typed_notification_http_cancellation_prevents_late_effects() {
    use std::future::Future;
    use std::task::Poll;

    let observations = with_notification_http(|_cx, server_cx, address, observations| async move {
        let mut exchange = Box::pin(notification_http_exchange(
            address,
            notification(7, true),
            true,
        ));
        while observations.started.load(Ordering::SeqCst) == 0 {
            assert!(
                std::future::poll_fn(|task| Poll::Ready(exchange.as_mut().poll(task)))
                    .await
                    .is_pending(),
                "uncompleted notification cannot be acknowledged"
            );
            asupersync::runtime::yield_now().await;
        }
        server_cx.cancel_with(
            asupersync::types::CancelKind::Shutdown,
            Some("cancel pending typed notification"),
        );
        if let Ok(response) = exchange.await {
            assert!(
                !response.starts_with(b"HTTP/1.1 202"),
                "cancelled work is not acknowledged as complete"
            );
        }
    });
    assert_eq!(observations.started.load(Ordering::SeqCst), 1);
    assert_eq!(observations.completed.load(Ordering::SeqCst), 0);
    assert_eq!(observations.total.load(Ordering::SeqCst), 0);
    assert_eq!(observations.abandoned.load(Ordering::SeqCst), 1);
}

#[test]
fn typed_notification_http_shutdown_settles_pending_work_after_sibling_completion() {
    use std::future::Future;
    use std::task::Poll;

    let observations = with_notification_http(|cx, server_cx, address, observations| async move {
        let mut pending = Box::pin(notification_http_exchange(
            address,
            notification(7, true),
            true,
        ));
        while observations.started.load(Ordering::SeqCst) == 0 {
            assert!(
                std::future::poll_fn(|task| Poll::Ready(pending.as_mut().poll(task)))
                    .await
                    .is_pending(),
                "pending notification must retain its response"
            );
            asupersync::runtime::yield_now().await;
        }

        let completed = notification_http_exchange(address, notification(11, false), true)
            .await
            .expect("independent notification completes while its sibling is pending");
        assert!(completed.starts_with(b"HTTP/1.1 202"));
        assert_eq!(observations.started.load(Ordering::SeqCst), 2);
        assert_eq!(observations.completed.load(Ordering::SeqCst), 1);
        assert_eq!(observations.total.load(Ordering::SeqCst), 33);

        server_cx.cancel_with(
            asupersync::types::CancelKind::Shutdown,
            Some("stop listener with one pending and one completed notification"),
        );
        if let Ok(response) = asupersync::time::timeout(cx.now(), Duration::from_secs(2), pending)
            .await
            .expect("listener shutdown closes pending notification without its 60-second deadline")
        {
            assert!(
                !response.starts_with(b"HTTP/1.1 202"),
                "incomplete notification cannot publish a success acknowledgement"
            );
        }
        assert!(cx.checkpoint().is_ok(), "the application caller stays live");
    });
    assert_eq!(observations.started.load(Ordering::SeqCst), 2);
    assert_eq!(observations.completed.load(Ordering::SeqCst), 1);
    assert_eq!(observations.total.load(Ordering::SeqCst), 33);
    assert_eq!(observations.abandoned.load(Ordering::SeqCst), 1);
}

#[test]
fn typed_notification_stdio_authenticates_and_drains_without_notification_responses() {
    exercise_notification_stdio(false);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn typed_notification_stdio_auto_selects_modern_before_current_message_activation() {
    exercise_notification_stdio(true);
}

fn exercise_notification_stdio(auto: bool) {
    use asupersync::net::{TcpListener, TcpStream};
    use fastmcp_rust::AsyncStdioTransport;

    const TOKEN: &str = "stdio-notification-owner";
    const FOREIGN_TOKEN: &str = "stdio-notification-foreign";

    let observations = Arc::new(NotificationObservations::default());
    let observed = Arc::clone(&observations);
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().expect("caller reactor"))
        .blocking_threads(0, 0)
        .build()
        .expect("caller-owned native stdio runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("caller context");
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let verifier = fastmcp_rust::StaticTokenVerifier::new([
                (TOKEN, fastmcp_rust::AuthContext::with_subject("owner")),
                (
                    FOREIGN_TOKEN,
                    fastmcp_rust::AuthContext::with_subject("foreign"),
                ),
            ])
            .expect("bounded test credentials");
            let registration = notification_registration(Arc::clone(&observations));
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("native NDJSON listener");
            let address = listener.local_addr().unwrap();
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    let (socket, _) = listener.accept().await.expect("native peer accepts");
                    let (input, output) = socket.into_split();
                    #[cfg(feature = "legacy-2024-11-05")]
                    if auto {
                        let server =
                            fastmcp_rust::auto::ServerBuilder::new("stdio-notifications", "1.0")
                                .extension(registration)
                                .expect("public Auto facade extension installation")
                                .auth_provider(fastmcp_rust::TokenAuthProvider::new(verifier))
                                .try_build()
                                .expect("frozen Auto server");
                        return server.serve_stdio_io(&server_cx, input, output).await;
                    }
                    #[cfg(not(feature = "legacy-2024-11-05"))]
                    assert!(!auto, "Auto requires the exact legacy adapter feature");
                    let server = modern::ServerBuilder::new("stdio-notifications", "1.0")
                        .extension(registration)
                        .expect("public modern facade extension installation")
                        .auth_provider(fastmcp_rust::TokenAuthProvider::new(verifier))
                        .try_build()
                        .expect("frozen modern server");
                    server.serve_stdio_io(&server_cx, input, output).await
                })
                .expect("owned stdio server task");
            let socket = TcpStream::connect(address)
                .await
                .expect("native peer connects");
            let (input, output) = socket.split();
            let mut peer = AsyncStdioTransport::from_io(input, output);
            let frame = |mut value: fastmcp_rust::JsonValue, token: Option<&str>| {
                if let Some(token) = token {
                    value["params"]["_meta"]["token"] = json!(token);
                }
                fastmcp_rust::serde_json::from_value::<JsonRpcMessage>(value)
                    .expect("valid JSON-RPC fixture")
            };
            let discovery = |id| {
                frame(
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "server/discover",
                        "params": {"_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {}
                        }}
                    }),
                    Some(TOKEN),
                )
            };
            peer.send_async(&cx, &discovery(81_i64)).await.unwrap();
            let JsonRpcMessage::Response(response) = peer.recv_async(&cx).await.unwrap() else {
                panic!("discovery returns its ordinary request response");
            };
            assert_eq!(response.id, Some(RequestId::Number(81)));
            assert!(response.error.is_none(), "{response:?}");

            let valid = notification(7, false);
            for token in [None, Some(FOREIGN_TOKEN)] {
                peer.send_async(&cx, &frame(valid.clone(), token))
                    .await
                    .unwrap();
            }
            peer.send_async(&cx, &frame(valid.clone(), Some(TOKEN)))
                .await
                .unwrap();
            while observations.completed.load(Ordering::SeqCst) == 0 {
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
            assert_eq!(
                observations.authorized.load(Ordering::SeqCst),
                1,
                "missing credentials and a different connection principal fail before policy"
            );
            assert_eq!(observations.started.load(Ordering::SeqCst), 1);
            assert_eq!(observations.total.load(Ordering::SeqCst), 21);

            let mut missing = valid.clone();
            missing["params"]["_meta"]
                .as_object_mut()
                .unwrap()
                .remove(ACTIVATION);
            let mut incompatible = valid.clone();
            incompatible["params"]["_meta"][ACTIVATION]["version"] = json!(2);
            let mut malformed = valid.clone();
            malformed["params"]["value"] = json!("wrong-type");
            let mut unexpected = valid.clone();
            unexpected["params"]["unexpected"] = json!(true);
            let mut unknown = valid;
            unknown["method"] = json!("com.example/unregistered");
            for rejected in [
                missing,
                incompatible,
                malformed,
                unexpected,
                unknown,
                notification(13, false),
            ] {
                peer.send_async(&cx, &frame(rejected, Some(TOKEN)))
                    .await
                    .unwrap();
            }
            let mut fresh = notification(11, false);
            fresh["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] =
                json!("2025-11-25");
            fresh["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
                json!({"extensions": {(EXTENSION): {"version": 2}}});
            peer.send_async(&cx, &frame(fresh, Some(TOKEN)))
                .await
                .unwrap();
            // Input EOF cancels still-running id-less children. Discovery is
            // allowed to overtake a notification, so wait for the callbacks
            // themselves before using EOF to verify complete wire silence.
            while observations.authorized.load(Ordering::SeqCst) < 5
                || observations.completed.load(Ordering::SeqCst) < 2
            {
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
            peer.send_async(&cx, &discovery(82_i64)).await.unwrap();

            // Half-close the actual socket, preserving the peer's reader.
            // Closing the transport itself would latch its terminal locally
            // and could hide an illegal notification response still on wire.
            socket
                .shutdown(std::net::Shutdown::Write)
                .expect("peer input EOF starts the server's accepted-work drain");
            let JsonRpcMessage::Response(response) = peer.recv_async(&cx).await.unwrap() else {
                panic!("only the explicit discovery request produces a response");
            };
            assert_eq!(response.id, Some(RequestId::Number(82)));
            assert!(response.error.is_none(), "{response:?}");
            assert!(
                matches!(peer.recv_async(&cx).await, Err(TransportError::Closed)),
                "successful and rejected notifications remain silent through actual wire EOF"
            );
            serving
                .join(&cx)
                .await
                .expect("owned stdio server joins")
                .expect("EOF drains every accepted notification");
            assert!(cx.checkpoint().is_ok(), "the application caller stays live");
        })
        .await
        .expect("bounded native NDJSON exchange and complete notification drain");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    assert_eq!(observed.authorized.load(Ordering::SeqCst), 5);
    assert_eq!(observed.started.load(Ordering::SeqCst), 2);
    assert_eq!(observed.completed.load(Ordering::SeqCst), 2);
    assert_eq!(observed.total.load(Ordering::SeqCst), 54);
    assert_eq!(observed.abandoned.load(Ordering::SeqCst), 0);
}

fn memory_notification_frame(
    mut value: fastmcp_rust::JsonValue,
    token: Option<&str>,
) -> JsonRpcMessage {
    if let Some(token) = token {
        value["params"]["_meta"]["token"] = json!(token);
    }
    fastmcp_rust::serde_json::from_value(value).expect("valid JSON-RPC fixture")
}

fn notification_discovery(id: i64) -> JsonRpcMessage {
    memory_notification_frame(
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "server/discover",
            "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }}
        }),
        Some("memory-notification-owner"),
    )
}

fn memory_notification_server(observations: Arc<NotificationObservations>) -> modern::Server {
    let verifier = fastmcp_rust::StaticTokenVerifier::new([
        (
            "memory-notification-owner",
            fastmcp_rust::AuthContext::with_subject("owner"),
        ),
        (
            "memory-notification-foreign",
            fastmcp_rust::AuthContext::with_subject("foreign"),
        ),
    ])
    .unwrap();
    modern::ServerBuilder::new("memory-notifications", "1.0")
        .extension(notification_registration(observations))
        .unwrap()
        .auth_provider(fastmcp_rust::TokenAuthProvider::new(verifier))
        .try_build()
        .unwrap()
}

#[test]
fn typed_notification_memory_authenticates_each_frame_and_revalidates_activation() {
    let observations = Arc::new(NotificationObservations::default());
    let observed = Arc::clone(&observations);
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let server = memory_notification_server(Arc::clone(&observations));
            let (mut peer, transport) = create_memory_transport_pair_with_capacity(1);
            let mut serving = cx
                .spawn(move |cx| async move { server.serve_memory(&cx, transport).await })
                .unwrap();
            peer.send_async(&cx, &notification_discovery(1))
                .await
                .unwrap();
            assert!(response(&cx, &mut peer, 1).await.error.is_none());

            let valid = notification(7, false);
            for token in [None, Some("memory-notification-foreign")] {
                peer.send_async(&cx, &memory_notification_frame(valid.clone(), token))
                    .await
                    .unwrap();
            }
            peer.send_async(
                &cx,
                &memory_notification_frame(valid.clone(), Some("memory-notification-owner")),
            )
            .await
            .unwrap();

            let mut missing = valid.clone();
            missing["params"]["_meta"]
                .as_object_mut()
                .unwrap()
                .remove(ACTIVATION);
            let mut incompatible = valid.clone();
            incompatible["params"]["_meta"][ACTIVATION]["version"] = json!(2);
            let mut malformed = valid.clone();
            malformed["params"]["value"] = json!("wrong-type");
            let mut extra_parameter = valid.clone();
            extra_parameter["params"]["unexpected"] = json!(true);
            let mut unknown = valid;
            unknown["method"] = json!("com.example/unregistered");
            for rejected in [
                missing,
                incompatible,
                malformed,
                extra_parameter,
                unknown,
                notification(13, false),
            ] {
                peer.send_async(
                    &cx,
                    &memory_notification_frame(rejected, Some("memory-notification-owner")),
                )
                .await
                .unwrap();
            }
            let mut fresh = notification(11, false);
            fresh["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] =
                json!("2025-11-25");
            fresh["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
                json!({"extensions": {(EXTENSION): {"version": 2}}});
            peer.send_async(
                &cx,
                &memory_notification_frame(fresh, Some("memory-notification-owner")),
            )
            .await
            .unwrap();
            // Input EOF cancels still-running id-less children. Discovery is
            // allowed to overtake a notification, so wait for the callbacks
            // themselves before using EOF to verify complete wire silence.
            while observations.authorized.load(Ordering::SeqCst) < 5
                || observations.completed.load(Ordering::SeqCst) < 2
            {
                asupersync::runtime::yield_now().await;
            }
            peer.send_async(&cx, &notification_discovery(2))
                .await
                .unwrap();
            let (mut input, output) = peer.into_split();
            drop(output);
            let JsonRpcMessage::Response(response) = input.recv_async(&cx).await.unwrap() else {
                panic!("only the explicit discovery request produces a response");
            };
            assert_eq!(response.id, Some(RequestId::Number(2)));
            assert!(response.error.is_none(), "{response:?}");
            assert!(matches!(
                input.recv_async(&cx).await,
                Err(TransportError::Closed)
            ));
            serving.join(&cx).await.unwrap().unwrap();
            assert!(cx.checkpoint().is_ok());
        })
        .await
        .expect("bounded native memory exchange and full notification drain");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    assert_eq!(observed.authorized.load(Ordering::SeqCst), 5);
    assert_eq!(observed.started.load(Ordering::SeqCst), 2);
    assert_eq!(observed.completed.load(Ordering::SeqCst), 2);
    assert_eq!(observed.total.load(Ordering::SeqCst), 54);
    assert_eq!(observed.abandoned.load(Ordering::SeqCst), 0);
}

#[test]
fn typed_notification_memory_shutdown_cancels_pending_work_without_blocking_siblings() {
    let observations = Arc::new(NotificationObservations::default());
    let observed = Arc::clone(&observations);
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let server = memory_notification_server(Arc::clone(&observations));
            let (mut peer, transport) = create_memory_transport_pair_with_capacity(1);
            let (sender, mut receiver) = asupersync::channel::oneshot::channel();
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    sender.send(&server_cx, server_cx.clone()).unwrap();
                    server.serve_memory(&server_cx, transport).await
                })
                .unwrap();
            let server_cx = receiver.recv(&cx).await.unwrap();
            peer.send_async(
                &cx,
                &memory_notification_frame(
                    notification(7, true),
                    Some("memory-notification-owner"),
                ),
            )
            .await
            .unwrap();
            while observations.started.load(Ordering::SeqCst) == 0 {
                asupersync::runtime::yield_now().await;
            }
            peer.send_async(&cx, &notification_discovery(1))
                .await
                .unwrap();
            assert!(response(&cx, &mut peer, 1).await.error.is_none());
            peer.send_async(
                &cx,
                &memory_notification_frame(
                    notification(11, false),
                    Some("memory-notification-owner"),
                ),
            )
            .await
            .unwrap();
            while observations.completed.load(Ordering::SeqCst) == 0 {
                asupersync::runtime::yield_now().await;
            }
            assert_eq!(observations.started.load(Ordering::SeqCst), 2);
            assert_eq!(observations.total.load(Ordering::SeqCst), 33);
            server_cx.cancel_with(
                asupersync::types::CancelKind::Shutdown,
                Some("stop pending native extension notification"),
            );
            assert!(matches!(
                asupersync::time::timeout(cx.now(), Duration::from_secs(2), peer.recv_async(&cx))
                    .await
                    .expect("shutdown does not wait for the notification deadline"),
                Err(TransportError::Closed)
            ));
            serving.join(&cx).await.unwrap().unwrap();
            assert!(cx.checkpoint().is_ok(), "caller authority stays live");
        })
        .await
        .expect("bounded native notification cancellation and cleanup");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    assert_eq!(observed.started.load(Ordering::SeqCst), 2);
    assert_eq!(observed.completed.load(Ordering::SeqCst), 1);
    assert_eq!(observed.total.load(Ordering::SeqCst), 33);
    assert_eq!(observed.abandoned.load(Ordering::SeqCst), 1);
}
