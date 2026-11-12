//! Client notifications cross independently admitted HTTP legs without waiters.

use super::*;

fn address(endpoint: CanonicalHttpUrl) -> std::net::SocketAddr {
    std::net::SocketAddr::new(endpoint.host().parse().unwrap(), endpoint.port().unwrap())
}

fn forward_notification(
    builder: ExtensionBuilder<ClientSettings, ServerSettings, Settings>,
    upstream: ExtensionHttpUpstream,
    authorized: Arc<AtomicUsize>,
) -> ExtensionBuilder<ClientSettings, ServerSettings, Settings> {
    builder
        .typed_http_proxy_notification(
            NOTIFICATION,
            "scaled-notification-v1",
            ACTIVATION,
            move |notification: &ScaleNotification| {
                authorized.fetch_add(1, Ordering::SeqCst);
                if notification.value == 17 {
                    return Err(McpError::new(
                        fastmcp_rust::McpErrorCode::ResourceForbidden,
                        "gateway notification policy denied the operation",
                    ));
                }
                Ok(())
            },
            upstream,
        )
        .unwrap()
}

fn duplex_gateway(
    upstream: ExtensionHttpUpstream,
    authorized: Arc<AtomicUsize>,
) -> modern::ServerBuilder {
    // Registering the notification first exercises the mixed contract path;
    // the sealed declaration still matches the upstream's method ordering.
    let registration = forward_notification(builder(), upstream.clone(), authorized)
        .typed_http_proxy_request::<ScaleRequest, ScaleResponse>(
            METHOD,
            "scale-params-v1",
            "scale-result-v1",
            upstream,
        )
        .unwrap()
        .build()
        .unwrap();
    modern::ServerBuilder::new("notification-gateway", "1.0")
        .extension(registration)
        .unwrap()
}

#[derive(Clone)]
struct UpstreamNotificationProbe(Arc<Mutex<Vec<JsonRpcRequest>>>);

impl Middleware for UpstreamNotificationProbe {
    fn on_request(
        &self,
        context: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        if request.method == NOTIFICATION {
            assert!(
                context.auth().is_none(),
                "downstream authentication is not upstream identity"
            );
            self.0.lock().unwrap().push(request.clone());
        }
        Ok(MiddlewareDecision::Continue)
    }
}

#[test]
fn typed_http_proxy_client_notifications_revalidate_each_leg_and_rebuild_proof() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observations = Arc::new(NotificationObservations::default());
    let retained = Arc::clone(&observations);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let retained_wire = Arc::clone(&observed);
    let server = modern::ServerBuilder::new("notification-producer", "1.0")
        .extension(duplex_registration(calls, Arc::clone(&observations)))
        .unwrap()
        .middleware(UpstreamNotificationProbe(observed));
    run_http_test(server, move |cx, endpoint| async move {
        let declaration_observations = Arc::new(NotificationObservations::default());
        let declaration_calls = Arc::new(AtomicUsize::new(0));
        let upstream = connect_upstream(
            &cx,
            endpoint,
            duplex_registration(
                Arc::clone(&declaration_calls),
                Arc::clone(&declaration_observations),
            ),
        )
        .await;
        assert!(
            builder()
                .typed_http_proxy_request::<ScaleRequest, ScaleResponse>(
                    METHOD, "scale-params-v1", "scale-result-v1", upstream.clone(),
                )
                .unwrap()
                .build()
                .is_err(),
            "a mixed upstream contract cannot omit the downstream notification route"
        );
        assert!(
            builder()
                .typed_http_proxy_notification(
                    NOTIFICATION,
                    "scaled-notification-v1",
                    "com.example/different-proof",
                    |_: &ScaleNotification| Ok(()),
                    upstream.clone(),
                )
                .is_err(),
            "a notification cannot substitute another activation proof location"
        );
        let authorized = Arc::new(AtomicUsize::new(0));
        let verifier = fastmcp_rust::StaticTokenVerifier::new([(
            "typed-notification-secret",
            fastmcp_rust::AuthContext::with_subject("gateway-caller"),
        )])
        .unwrap();
        let gateway = duplex_gateway(upstream, Arc::clone(&authorized))
            .auth_provider(fastmcp_rust::TokenAuthProvider::new(verifier));
        with_http_server(&cx, gateway, |endpoint| async {
            let address = address(endpoint);
            let valid = notification(7, false);
            let unauthenticated = notification_http_exchange(address, valid.clone(), false)
                .await.unwrap();
            assert!(unauthenticated.starts_with(b"HTTP/1.1 401"));
            assert_eq!(authorized.load(Ordering::SeqCst), 0);
            assert_eq!(observations.authorized.load(Ordering::SeqCst), 0);

            let accepted = notification_http_exchange(address, valid.clone(), true)
                .await.unwrap();
            assert!(accepted.starts_with(b"HTTP/1.1 202"));
            assert!(
                accepted.ends_with(b"\r\n\r\n"),
                "no JSON-RPC response is invented"
            );
            assert_eq!(observations.completed.load(Ordering::SeqCst), 1);
            assert_eq!(observations.total.load(Ordering::SeqCst), 21);

            let mut missing = valid.clone();
            missing["params"]["_meta"].as_object_mut().unwrap().remove(ACTIVATION);
            let mut incompatible = valid.clone();
            incompatible["params"]["_meta"][ACTIVATION]["version"] = json!(2);
            let mut malformed = valid.clone();
            malformed["params"]["value"] = json!("wrong-type");
            let mut unexpected = valid.clone();
            unexpected["params"]["unexpected"] = json!(true);
            let mut request_shaped = valid.clone();
            request_shaped["id"] = json!(41);
            for rejected in [missing, incompatible, malformed, unexpected, request_shaped] {
                let response = notification_http_exchange(address, rejected, true).await.unwrap();
                assert!(response.starts_with(b"HTTP/1.1 400"));
                assert_eq!(observations.authorized.load(Ordering::SeqCst), 1);
                assert_eq!(observations.started.load(Ordering::SeqCst), 1);
            }
            let denied = notification_http_exchange(address, notification(17, false), true)
                .await.unwrap();
            assert!(denied.starts_with(b"HTTP/1.1 403"));
            assert_eq!(observations.authorized.load(Ordering::SeqCst), 1);
            let upstream_denied = notification_http_exchange(address, notification(13, false), true)
                .await.unwrap();
            assert!(upstream_denied.starts_with(b"HTTP/1.1 400"));
            assert_eq!(observations.authorized.load(Ordering::SeqCst), 2);
            assert_eq!(observations.started.load(Ordering::SeqCst), 1);

            let mut fresh = notification(11, false);
            fresh["params"]["_meta"]["com.example/downstream-only"] = json!("do-not-forward");
            fresh["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2025-11-25");
            fresh["params"]["_meta"]["io.modelcontextprotocol/clientInfo"] =
                json!({"name": "spoofed-downstream", "version": "0"});
            let accepted = notification_http_exchange(address, fresh, true).await.unwrap();
            assert!(accepted.starts_with(b"HTTP/1.1 202"));
            assert_eq!(observations.total.load(Ordering::SeqCst), 54);
        })
        .await;
        assert_eq!(declaration_calls.load(Ordering::SeqCst), 0);
        assert_eq!(declaration_observations.authorized.load(Ordering::SeqCst), 0);
        assert_eq!(declaration_observations.started.load(Ordering::SeqCst), 0);
    });
    assert_eq!(retained.completed.load(Ordering::SeqCst), 2);
    assert_eq!(retained.abandoned.load(Ordering::SeqCst), 0);
    let received = retained_wire.lock().unwrap();
    assert_eq!(received.len(), 2);
    for request in received.iter() {
        assert!(request.id.is_none(), "notifications never allocate a response waiter");
        assert_eq!(
            request.params.as_ref().unwrap()["_meta"],
            json!({(ACTIVATION): {"version": 1}})
        );
    }
}

#[test]
fn typed_http_proxy_client_notification_drop_releases_both_legs_and_keeps_requests_usable() {
    let calls = Arc::new(AtomicUsize::new(0));
    let retained_calls = Arc::clone(&calls);
    let observations = Arc::new(NotificationObservations::default());
    let retained = Arc::clone(&observations);
    let server = modern::ServerBuilder::new("cancellable-notification-producer", "1.0")
        .extension(duplex_registration(calls, Arc::clone(&observations)))
        .unwrap();
    run_http_test(server, move |cx, endpoint| async move {
        let upstream = connect_upstream(
            &cx, endpoint,
            duplex_registration(
                Arc::new(AtomicUsize::new(0)),
                Arc::new(NotificationObservations::default()),
            ),
        )
        .await;
        let gateway = duplex_gateway(upstream, Arc::new(AtomicUsize::new(0)));
        with_http_server(&cx, gateway, |endpoint| async {
            let (id, descriptors, discovery) = client_configuration_with_notifications(true);
            let mut client = modern::ClientBuilder::new()
                .extension_registry(descriptors, discovery, || accept_settings)
                .unwrap()
                .connect_http_with_cx(&cx, endpoint.clone())
                .await
                .unwrap();
            let mut held = Box::pin(notification_http_exchange(
                address(endpoint), notification(7, true), false,
            ));
            while observations.started.load(Ordering::SeqCst) == 0 {
                assert!(
                    std::future::poll_fn(|task| Poll::Ready(held.as_mut().poll(task)))
                        .await.is_pending()
                );
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
            assert_eq!(
                client.request_final_extension(&cx, &id, METHOD, json!({"value": 11}))
                    .await.unwrap(),
                json!({"value": 33})
            );
            assert_eq!(observations.abandoned.load(Ordering::SeqCst), 0);
            drop(held);
            asupersync::time::timeout(cx.now(), Duration::from_secs(2), async {
                while observations.abandoned.load(Ordering::SeqCst) == 0 {
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("dropping the caller's POST closes both owned HTTP legs");
            assert_eq!(
                observations.started.load(Ordering::SeqCst), 1,
                "no automatic replay"
            );
            assert_eq!(observations.completed.load(Ordering::SeqCst), 0);
            assert!(cx.checkpoint().is_ok());
            client.notify_final_extension(
                &cx, &id, NOTIFICATION, json!({"value": 11, "hold": false}),
            )
            .await
            .expect("a new independent notification succeeds after the abandoned POST");
            assert_eq!(
                client.request_final_extension(&cx, &id, METHOD, json!({"value": 17}))
                    .await.unwrap(),
                json!({"value": 51})
            );
        })
        .await;
    });
    assert_eq!(retained_calls.load(Ordering::SeqCst), 2);
    assert_eq!(retained.started.load(Ordering::SeqCst), 2);
    assert_eq!(retained.completed.load(Ordering::SeqCst), 1);
    assert_eq!(retained.abandoned.load(Ordering::SeqCst), 1);
    assert_eq!(retained.total.load(Ordering::SeqCst), 33);
}

fn settings_builder(
    multiplier: u32,
    resolved: Arc<AtomicUsize>,
) -> ExtensionBuilder<ClientSettings, ServerSettings, Settings> {
    ExtensionBuilder::new(
        EXTENSION, 1, "typed-math-client-v1", "typed-math-server-v1",
        ServerSettings { version: 1, multiplier },
        move |client: ClientSettings, server: ServerSettings| {
            if client.version != server.version {
                return Err(McpError::invalid_params("incompatible math version"));
            }
            Ok(Settings {
                multiplier: u32::try_from(resolved.load(Ordering::SeqCst)).unwrap(),
            })
        },
    )
    .unwrap()
}

#[test]
fn typed_http_proxy_client_notifications_refuse_settings_mismatch_and_fresh_resolver_drift() {
    let observations = Arc::new(NotificationObservations::default());
    let retained = Arc::clone(&observations);
    let server = modern::ServerBuilder::new("notification-settings-producer", "1.0")
        .extension(notification_registration(Arc::clone(&observations)))
        .unwrap();
    run_http_test(server, move |cx, endpoint| async move {
        let resolved = Arc::new(AtomicUsize::new(3));
        let declaration = settings_builder(3, Arc::clone(&resolved))
            .typed_notification_sync(
                NOTIFICATION, "scaled-notification-v1", ACTIVATION,
                |_: &ScaleNotification| Ok(()),
                |_: ExtensionNotificationContext<'_, Settings>, _: ScaleNotification| Ok(()),
            )
            .unwrap()
            .build()
            .unwrap();
        let upstream = connect_upstream(&cx, endpoint, declaration).await;
        let changed = forward_notification(
            settings_builder(5, Arc::new(AtomicUsize::new(5))),
            upstream.clone(),
            Arc::new(AtomicUsize::new(0)),
        )
        .build()
        .unwrap();
        let changed = modern::ServerBuilder::new("different-notification-settings", "1.0")
            .extension(changed)
            .unwrap();
        with_http_server(&cx, changed, |endpoint| async {
            let refused = notification_http_exchange(
                address(endpoint), notification(7, false), false,
            )
            .await
            .unwrap();
            assert!(refused.starts_with(b"HTTP/1.1 400"));
            assert_eq!(observations.authorized.load(Ordering::SeqCst), 0);
        })
        .await;

        let registration = forward_notification(
            builder(), upstream, Arc::new(AtomicUsize::new(0)),
        )
        .build()
        .unwrap();
        let gateway = modern::ServerBuilder::new("stable-notification-settings", "1.0")
            .extension(registration)
            .unwrap();
        with_http_server(&cx, gateway, |endpoint| async {
            let address = address(endpoint);
            let accepted = notification_http_exchange(address, notification(7, false), false)
                .await.unwrap();
            assert!(accepted.starts_with(b"HTTP/1.1 202"));
            resolved.store(5, Ordering::SeqCst);
            let refused = notification_http_exchange(address, notification(11, false), false)
                .await.unwrap();
            assert!(refused.starts_with(b"HTTP/1.1 400"));
            assert_eq!(observations.authorized.load(Ordering::SeqCst), 1);
            assert_eq!(observations.completed.load(Ordering::SeqCst), 1);
            resolved.store(3, Ordering::SeqCst);
            let accepted = notification_http_exchange(address, notification(11, false), false)
                .await.unwrap();
            assert!(accepted.starts_with(b"HTTP/1.1 202"));
        })
        .await;
    });
    assert_eq!(retained.completed.load(Ordering::SeqCst), 2);
    assert_eq!(retained.total.load(Ordering::SeqCst), 54);
}

fn forged_notification_registration(calls: Arc<AtomicUsize>) -> ExtensionRegistration {
    builder()
        .typed_notification_sync(
            NOTIFICATION, "forged-notification-v1", ACTIVATION,
            |_: &ForgedRequest| Ok(()),
            move |_: ExtensionNotificationContext<'_, Settings>, _: ForgedRequest| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn typed_http_proxy_client_notifications_reject_synthesized_metadata_before_peer_contact() {
    let calls = Arc::new(AtomicUsize::new(0));
    let retained = Arc::clone(&calls);
    let server = modern::ServerBuilder::new("forged-notification-producer", "1.0")
        .extension(forged_notification_registration(calls))
        .unwrap();
    run_http_test(server, move |cx, endpoint| async move {
        let upstream = connect_upstream(
            &cx, endpoint, forged_notification_registration(Arc::new(AtomicUsize::new(0))),
        )
        .await;
        let registration = builder()
            .typed_http_proxy_notification(
                NOTIFICATION, "forged-notification-v1", ACTIVATION,
                |_: &ForgedRequest| Ok(()), upstream,
            )
            .unwrap()
            .build()
            .unwrap();
        let gateway = modern::ServerBuilder::new("forged-notification-gateway", "1.0")
            .extension(registration)
            .unwrap();
        with_http_server(&cx, gateway, |endpoint| async {
            let response = notification_http_exchange(
                address(endpoint),
                json!({
                    "jsonrpc": "2.0", "method": NOTIFICATION,
                    "params": {"value": 7, "_meta": {(ACTIVATION): {"version": 1}}}
                }),
                false,
            )
            .await
            .unwrap();
            assert!(response.starts_with(b"HTTP/1.1 400"));
        })
        .await;
    });
    assert_eq!(retained.load(Ordering::SeqCst), 0);
}
