use super::*;
use asupersync::runtime::RuntimeBuilder;
use fastmcp_protocol::extensions::{
    ExtensionDescriptor, ExtensionDirection, ExtensionFallbackPolicy, ExtensionHttpEraDisposition,
    ExtensionMethodDescriptor, ExtensionNegotiationError, ExtensionNegotiationResolver,
    ExtensionNotificationDescriptor, ExtensionSettings, ExtensionSettingsSchema,
    NotificationActivationProofDescriptor, NotificationActivationProofLocation,
};
use fastmcp_transport::memory::create_memory_transport_pair_with_capacity;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

const METHOD: &str = "example/echo";
const NOTIFICATION: &str = "example/event";
const RESULT: &str = "com.example/raw-result";
const PROOF: &str = "com.example/activation";

fn run<F: Future<Output = ()>>(test: impl FnOnce(Cx) -> F) {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(5), test(cx))
            .await
            .expect("memory extensions must progress on the caller runtime");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn id() -> ExtensionId {
    ExtensionId::parse("com.example/raw").unwrap()
}

fn info() -> ClientInfo {
    ClientInfo {
        name: "extension-memory-client".to_owned(),
        version: "1".to_owned(),
    }
}

fn descriptor(location: NotificationActivationProofLocation) -> ExtensionDescriptor {
    ExtensionDescriptor {
        id: id(),
        client_settings: ExtensionSettingsSchema {
            schema_id: "raw-client-v1".to_owned(),
            codec_id: "raw-client-codec-v1".to_owned(),
        },
        server_settings: ExtensionSettingsSchema {
            schema_id: "raw-server-v1".to_owned(),
            codec_id: "raw-server-codec-v1".to_owned(),
        },
        resolver: ExtensionNegotiationResolver {
            id: "raw-compatibility-v1".to_owned(),
            version: 1,
            fallback: ExtensionFallbackPolicy::RejectOneSided,
        },
        method: Some(ExtensionMethodDescriptor {
            name: METHOD.to_owned(),
            direction: ExtensionDirection::ClientToServer,
            http_era_disposition: Some(ExtensionHttpEraDisposition::ModernExclusive),
            legacy_fallback: false,
        }),
        notification: Some(ExtensionNotificationDescriptor {
            name: NOTIFICATION.to_owned(),
            direction: ExtensionDirection::ClientToServer,
            activation_proof: Some(NotificationActivationProofDescriptor::SelfContained {
                location,
                key: PROOF.to_owned(),
            }),
        }),
        result_discriminator: Some(RESULT.to_owned()),
        routing_headers: Vec::new(),
        stdio_correlation: None,
    }
}

fn compatible(
    descriptor: &ExtensionDescriptor,
    client: &ExtensionSettings,
    server: &ExtensionSettings,
) -> Result<ExtensionSettings, ExtensionNegotiationError> {
    if client.as_object() != server.as_object() {
        return Err(ExtensionNegotiationError::SettingsCompatibilityRejected(
            descriptor.id.to_string(),
        ));
    }
    Ok(client.clone())
}

fn builder(descriptor: ExtensionDescriptor) -> (MemoryClientBuilder, Arc<AtomicUsize>) {
    let mut registry = ExtensionDescriptorRegistry::new();
    registry.register(descriptor).unwrap();
    let settings = ClientExtensionDiscovery {
        extensions: BTreeMap::from([(
            id(),
            ExtensionSettings::new(json!({"mode":"raw"})).unwrap(),
        )]),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver_calls = Arc::clone(&calls);
    let builder = MemoryClient::builder(info())
        .extension_registry(registry, settings, move || {
            resolver_calls.fetch_add(1, Ordering::SeqCst);
            compatible
        })
        .unwrap();
    (builder, calls)
}

fn discovery(advertise: bool) -> Value {
    let extensions = if advertise {
        json!({"com.example/raw":{"mode":"raw"}})
    } else {
        json!({})
    };
    json!({"resultType":"complete", "supportedVersions":["2026-07-28"],
        "capabilities":{"extensions":extensions}, "ttlMs":0, "cacheScope":"private"})
}

fn response(request_id: i64, result: Value) -> JsonRpcMessage {
    JsonRpcMessage::Response(JsonRpcResponse::success(
        RequestId::Number(request_id),
        result,
    ))
}

fn tools() -> Value {
    json!({"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"})
}

async fn receive(
    cx: &Cx,
    peer: &mut MemoryTransport,
    method: &str,
    request_id: Option<i64>,
) -> JsonRpcRequest {
    let JsonRpcMessage::Request(request) = peer.recv_async(cx).await.unwrap() else {
        panic!("expected client request");
    };
    assert_eq!(request.method, method);
    assert_eq!(request.id, request_id.map(RequestId::Number));
    request
}

async fn connected_with(
    cx: &Cx,
    builder: MemoryClientBuilder,
    advertise: bool,
) -> (MemoryClient, MemoryTransport) {
    let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
    peer.send_async(cx, &response(1, discovery(advertise)))
        .await
        .unwrap();
    let client = builder.connect(cx, transport).await.unwrap();
    let request = receive(cx, &mut peer, "server/discover", Some(1)).await;
    assert_eq!(
        request.params.unwrap()["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
        json!({"com.example/raw":{"mode":"raw"}})
    );
    (client, peer)
}

async fn connected(cx: &Cx) -> (MemoryClient, MemoryTransport, Arc<AtomicUsize>) {
    let (builder, calls) = builder(descriptor(NotificationActivationProofLocation::Params));
    let (client, peer) = connected_with(cx, builder, true).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    (client, peer, calls)
}

async fn extension_result(
    cx: &Cx,
    client: &mut MemoryClient,
    execution: &mut MemoryExtensionExecution,
) -> McpResult<Value> {
    loop {
        match client
            .next_extension_event(cx, &McpRequestCancellation::new(), execution)
            .await?
        {
            Some(MemoryExtensionEvent::Result(value)) => return Ok(value),
            Some(MemoryExtensionEvent::Notification(_)) => {}
            None => panic!("extension lost its terminal result"),
        }
    }
}

#[test]
fn memory_extension_current_waiter_cancellation_precedes_buffered_progress() {
    run(|cx| async move {
        for terminal_before_wait in [false, true] {
            for cause in ["live", "token", "caller", "deadline"] {
                let (mut client, mut peer, _) = connected(&cx).await;
                let original = McpRequestCancellation::new();
                let live = McpRequestCancellation::new();
                let observer = McpRequestCancellation::new();
                let mut owner = client
                    .execute_final_extension(
                        &cx,
                        &original,
                        &id(),
                        METHOD,
                        json!({"_meta":{"progressToken":"buffered"}}),
                    )
                    .await
                    .unwrap();
                receive(&cx, &mut peer, METHOD, Some(2)).await;
                let mut sibling = client
                    .execute_final_extension(&cx, &live, &id(), METHOD, json!({}))
                    .await
                    .unwrap();
                receive(&cx, &mut peer, METHOD, Some(3)).await;
                peer.send_async(
                    &cx,
                    &JsonRpcMessage::Request(JsonRpcRequest::notification(
                        "notifications/progress",
                        Some(json!({"progressToken":"buffered","progress":1})),
                    )),
                )
                .await
                .unwrap();
                client.drive_once(&cx, &live).await.unwrap();
                if terminal_before_wait {
                    peer.send_async(&cx, &response(2, json!({"resultType":RESULT,"value":7})))
                        .await
                        .unwrap();
                    client.drive_once(&cx, &live).await.unwrap();
                }
                let waiter = match cause {
                    "caller" => {
                        let stopped = Cx::for_testing();
                        stopped.set_cancel_requested(true);
                        stopped
                    }
                    "deadline" => Cx::for_testing_with_budget(
                        asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
                    ),
                    _ => cx.clone(),
                };
                if cause == "token" {
                    assert!(observer.cancel());
                }
                let event = client
                    .next_extension_event(&waiter, &observer, &mut owner)
                    .await;
                if cause == "live" || terminal_before_wait {
                    assert!(matches!(
                        event.unwrap(),
                        Some(MemoryExtensionEvent::Notification(_))
                    ));
                    if !terminal_before_wait {
                        peer.send_async(&cx, &response(2, json!({"resultType":RESULT,"value":7})))
                            .await
                            .unwrap();
                    }
                    assert_eq!(
                        extension_result(&cx, &mut client, &mut owner).await.unwrap()["value"],
                        7
                    );
                    assert!(owner.raw_result_source().is_some());
                    assert!(client.take_cancellation_events().is_empty());
                } else {
                    assert_eq!(
                        event.unwrap_err().code,
                        McpErrorCode::RequestCancelled,
                        "{cause}"
                    );
                    assert!(
                        client
                            .next_extension_event(&waiter, &observer, &mut owner)
                            .await
                            .unwrap()
                            .is_none()
                    );
                    assert!(owner.notifications.is_empty());
                    assert!(owner.raw_result_source().is_none());
                    let events = client.take_cancellation_events();
                    assert_eq!(events.len(), 1);
                    assert_eq!(events[0].request_id, RequestId::Number(2));
                    assert_eq!(
                        events[0].reason,
                        crate::ExecutionTerminalReason::CallerCancelled
                    );
                    client.drive_once(&cx, &live).await.unwrap();
                    let control =
                        receive(&cx, &mut peer, "notifications/cancelled", None).await;
                    assert_eq!(control.params.unwrap()["requestId"], 2);
                }
                peer.send_async(&cx, &response(3, json!({"resultType":RESULT,"value":9})))
                    .await
                    .unwrap();
                assert_eq!(
                    extension_result(&cx, &mut client, &mut sibling).await.unwrap()["value"],
                    9
                );
                assert!(!original.is_cancel_requested());
                assert!(!live.is_cancel_requested());
                assert!(cx.checkpoint().is_ok());
                assert!(client.executor.terminal_error().is_none());
                client.close(&cx).unwrap();
            }
        }
    });
}

#[test]
fn memory_extensions_preserve_owned_progress_exact_source_and_reordered_siblings() {
    run(|cx| async move {
        let (mut client, mut peer, _) = connected(&cx).await;
        let mut server = cx
            .spawn(move |peer_cx| async move {
                let extension = receive(&peer_cx, &mut peer, METHOD, Some(2)).await;
                let meta = &extension.params.as_ref().unwrap()["_meta"];
                assert_eq!(
                    meta["io.modelcontextprotocol/protocolVersion"],
                    "2026-07-28"
                );
                assert_eq!(
                    meta["io.modelcontextprotocol/clientInfo"]["name"],
                    "extension-memory-client"
                );
                assert_eq!(
                    meta["io.modelcontextprotocol/clientCapabilities"]["extensions"],
                    json!({"com.example/raw":{"mode":"raw"}})
                );
                assert_eq!(meta["com.example/note"], "retained");
                receive(&peer_cx, &mut peer, "tools/list", Some(3)).await;
                peer.send_async(&peer_cx, &response(3, tools()))
                    .await
                    .unwrap();
                for token in ["other", "owned"] {
                    peer.send_async(
                        &peer_cx,
                        &JsonRpcMessage::Request(JsonRpcRequest::notification(
                            "notifications/progress",
                            Some(json!({"progressToken":token,"progress":1})),
                        )),
                    )
                    .await
                    .unwrap();
                }
                let mut result = json!({"resultType":RESULT});
                for (name, source) in [
                    ("number", "1.20e+4"),
                    ("zero", "-0"),
                    ("large", "123456789012345678901234567890"),
                ] {
                    result[name] =
                        Value::Number(serde_json::Number::from_string_unchecked(source.to_owned()));
                }
                peer.send_async(&peer_cx, &response(2, result))
                    .await
                    .unwrap();
                peer
            })
            .unwrap();
        let live = McpRequestCancellation::new();
        let mut extension = client.execute_final_extension(&cx, &live, &id(), METHOD, json!({
            "_meta":{"progressToken":"owned", "com.example/note":"retained",
                "io.modelcontextprotocol/protocolVersion":"2024-11-05",
                "io.modelcontextprotocol/clientInfo":{"name":"spoof","version":"9"},
                "io.modelcontextprotocol/clientCapabilities":{"extensions":{"com.example/forged":{}}}}
        })).await.unwrap();
        assert_eq!(extension.request_id(), &RequestId::Number(2));
        assert!(extension.raw_result_source().is_none());
        let mut core = client
            .execute_core(&cx, &live, "tools/list", json!({}))
            .await
            .unwrap();
        let Some(MemoryExtensionEvent::Notification(progress)) = client
            .next_extension_event(&cx, &live, &mut extension)
            .await
            .unwrap()
        else {
            panic!("extension progress precedes its terminal result");
        };
        assert_eq!(progress.params.unwrap()["progressToken"], "owned");
        assert!(matches!(
            client.next_event(&cx, &live, &mut core).await.unwrap(),
            Some(MemoryRequestEvent::Result(_))
        ));
        let result = extension_result(&cx, &mut client, &mut extension)
            .await
            .unwrap();
        assert_eq!(result["resultType"], RESULT);
        let source = extension.raw_result_source().unwrap();
        for exact in ["1.20e+4", "-0", "123456789012345678901234567890"] {
            assert!(source.contains(exact), "exact number source {exact}");
        }
        assert_eq!(client.take_server_notifications().len(), 1);
        assert!(
            client
                .next_extension_event(&cx, &live, &mut extension)
                .await
                .unwrap()
                .is_none()
        );
        let _peer = server.join(&cx).await.unwrap();
        client.close(&cx).unwrap();
    });
}

#[test]
fn memory_extensions_reject_unowned_results_without_poisoning_an_admitted_sibling() {
    run(|cx| async move {
        for rejected in [
            json!({"resultType":"com.example/other-result"}),
            json!({"resultType":"task"}),
            json!({"resultType":null}),
            json!({"resultType":RESULT,"_meta":[]}),
        ] {
            let (mut client, mut peer, _) = connected(&cx).await;
            let mut server = cx
                .spawn(move |peer_cx| async move {
                    receive(&peer_cx, &mut peer, METHOD, Some(2)).await;
                    receive(&peer_cx, &mut peer, METHOD, Some(3)).await;
                    peer.send_async(&peer_cx, &response(2, rejected))
                        .await
                        .unwrap();
                    peer.send_async(
                        &peer_cx,
                        &response(3, json!({"resultType":RESULT,"value":7})),
                    )
                    .await
                    .unwrap();
                    peer
                })
                .unwrap();
            let live = McpRequestCancellation::new();
            let mut rejected = client
                .execute_final_extension(&cx, &live, &id(), METHOD, json!({}))
                .await
                .unwrap();
            let mut sibling = client
                .execute_final_extension(&cx, &live, &id(), METHOD, json!({}))
                .await
                .unwrap();
            assert_eq!(
                extension_result(&cx, &mut client, &mut sibling)
                    .await
                    .unwrap()["value"],
                7
            );
            assert_eq!(
                extension_result(&cx, &mut client, &mut rejected)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::InvalidRequest
            );
            assert!(rejected.raw_result_source().is_none());
            assert!(
                client
                    .next_extension_event(&cx, &live, &mut rejected)
                    .await
                    .unwrap()
                    .is_none()
            );
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        }
    });
}

#[test]
fn memory_extension_configuration_requires_local_authority_and_bilateral_support() {
    run(|cx| async move {
        for configured in [false, true] {
            let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
            let builder = if configured {
                builder(descriptor(NotificationActivationProofLocation::Params)).0
            } else {
                MemoryClientBuilder::new(info())
            };
            let builder = builder.capabilities(ClientCapabilities {
                extensions: Some(BTreeMap::from([(
                    "com.example/forged".to_owned(),
                    json!({}),
                )])),
                ..ClientCapabilities::default()
            });
            assert_eq!(
                builder.connect(&cx, transport).await.unwrap_err().code,
                McpErrorCode::InvalidParams
            );
            assert!(
                peer.recv_async(&cx).await.is_err(),
                "invalid configuration published no discovery"
            );
        }
        let mut missing_registry = ClientExtensionDiscovery::default();
        missing_registry
            .extensions
            .insert(id(), ExtensionSettings::new(json!({})).unwrap());
        assert!(
            MemoryClientBuilder::new(info())
                .extension_registry(ExtensionDescriptorRegistry::new(), missing_registry, || {
                    compatible
                })
                .is_err()
        );

        // A missing peer advertisement can select an inactive connection,
        // but it cannot grant execution or notification authority.
        let mut inactive = descriptor(NotificationActivationProofLocation::Params);
        inactive.resolver.fallback = ExtensionFallbackPolicy::ClientInactiveFallback;
        let (inactive_builder, _) = builder(inactive);
        let (mut client, mut peer) = connected_with(&cx, inactive_builder, false).await;
        let live = McpRequestCancellation::new();
        assert_eq!(
            client
                .execute_final_extension(&cx, &live, &id(), METHOD, json!({}))
                .await
                .unwrap_err()
                .code,
            McpErrorCode::InvalidParams
        );
        assert_eq!(
            client
                .notify_final_extension(&cx, &live, &id(), NOTIFICATION, json!({}))
                .await
                .unwrap_err()
                .code,
            McpErrorCode::InvalidParams
        );
        assert_eq!(client.next_id, 2);
        client.close(&cx).unwrap();
        assert!(peer.recv_async(&cx).await.is_err());

        let mut reversed = descriptor(NotificationActivationProofLocation::Params);
        let method = reversed.method.as_mut().unwrap();
        method.direction = ExtensionDirection::ServerToClient;
        method.http_era_disposition = None;
        let (reversed_builder, _) = builder(reversed);
        let (mut client, mut peer) = connected_with(&cx, reversed_builder, true).await;
        assert_eq!(
            client
                .execute_final_extension(&cx, &live, &id(), METHOD, json!({}))
                .await
                .unwrap_err()
                .code,
            McpErrorCode::InvalidParams
        );
        assert_eq!(client.next_id, 2);
        client.close(&cx).unwrap();
        assert!(peer.recv_async(&cx).await.is_err());
    });
}

#[test]
fn memory_extension_refusals_and_unsent_waits_allocate_no_ids_or_controls() {
    run(|cx| async move {
        let (mut client, mut peer, _) = connected(&cx).await;
        let live = McpRequestCancellation::new();
        let mut first = client
            .execute_final_extension(&cx, &live, &id(), METHOD, json!({}))
            .await
            .unwrap();
        let original = client.executor.pending_records();
        for (owner, method, params) in [
            (
                ExtensionId::parse("com.example/unknown").unwrap(),
                METHOD,
                json!({}),
            ),
            (id(), "example/unknown", json!({})),
            (id(), "tools/list", json!({})),
            (id(), METHOD, json!({"_meta":[]})),
        ] {
            assert_eq!(
                client
                    .execute_final_extension(&cx, &live, &owner, method, params)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::InvalidParams
            );
            assert_eq!(client.next_id, 3);
            assert_eq!(client.executor.pending_records(), original);
        }
        assert_eq!(
            client
                .execute_core(&cx, &live, METHOD, json!({}))
                .await
                .unwrap_err()
                .code,
            McpErrorCode::InvalidParams
        );
        for drop_wait in [false, true] {
            let cancellation = McpRequestCancellation::new();
            {
                let extension_id = id();
                let mut pending = pin!(client.execute_final_extension(
                    &cx,
                    &cancellation,
                    &extension_id,
                    METHOD,
                    json!({})
                ));
                poll_fn(|task| {
                    assert!(pending.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                if !drop_wait {
                    cancellation.cancel();
                    assert_eq!(
                        pending.await.unwrap_err().code,
                        McpErrorCode::RequestCancelled
                    );
                }
            }
            assert_eq!(client.next_id, 3);
            assert_eq!(client.executor.pending_records(), original);
            assert!(!client.executor.has_external_controls(&cx).unwrap());
        }
        receive(&cx, &mut peer, METHOD, Some(2)).await;
        peer.send_async(&cx, &response(2, json!({"resultType":RESULT,"value":1})))
            .await
            .unwrap();
        assert_eq!(
            extension_result(&cx, &mut client, &mut first)
                .await
                .unwrap()["value"],
            1
        );
        let mut next = client
            .execute_final_extension(&cx, &live, &id(), METHOD, json!({}))
            .await
            .unwrap();
        receive(&cx, &mut peer, METHOD, Some(3)).await;
        peer.send_async(&cx, &response(3, json!({"resultType":RESULT,"value":2})))
            .await
            .unwrap();
        assert_eq!(
            extension_result(&cx, &mut client, &mut next).await.unwrap()["value"],
            2
        );
        client.close(&cx).unwrap();
    });
}

#[test]
fn memory_extension_cancellation_and_drop_keep_late_results_out_of_siblings() {
    run(|cx| async move {
        for mode in 0..3 {
            let (mut client, mut peer, _) = connected(&cx).await;
            let original = McpRequestCancellation::new();
            let live = McpRequestCancellation::new();
            let mut cancelled = Some(
                client
                    .execute_final_extension(&cx, &original, &id(), METHOD, json!({}))
                    .await
                    .unwrap(),
            );
            receive(&cx, &mut peer, METHOD, Some(2)).await;
            let mut sibling = client
                .execute_final_extension(&cx, &live, &id(), METHOD, json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, METHOD, Some(3)).await;
            match mode {
                0 => {
                    original.cancel();
                }
                1 => {
                    drop(cancelled.take());
                }
                _ => client
                    .cancel_extension(&cx, cancelled.as_mut().unwrap())
                    .unwrap(),
            }
            let mut server = cx
                .spawn(move |peer_cx| async move {
                    let notification =
                        receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                    assert_eq!(notification.params.unwrap()["requestId"], 2);
                    // Even an invalid late result stays with the retired ID.
                    peer.send_async(
                        &peer_cx,
                        &response(2, json!({"resultType":"com.example/forged"})),
                    )
                    .await
                    .unwrap();
                    peer.send_async(
                        &peer_cx,
                        &response(3, json!({"resultType":RESULT,"value":9})),
                    )
                    .await
                    .unwrap();
                    peer
                })
                .unwrap();
            assert_eq!(
                extension_result(&cx, &mut client, &mut sibling)
                    .await
                    .unwrap()["value"],
                9
            );
            if let Some(cancelled) = &mut cancelled {
                assert_eq!(
                    extension_result(&cx, &mut client, cancelled)
                        .await
                        .unwrap_err()
                        .code,
                    McpErrorCode::RequestCancelled
                );
                assert!(
                    client
                        .next_extension_event(&cx, &live, cancelled)
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            assert_eq!(client.take_cancellation_events().len(), 1);
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        }
    });
}

#[test]
fn memory_extension_notifications_publish_fresh_proof_without_request_state() {
    run(|cx| async move {
        for location in [
            NotificationActivationProofLocation::Params,
            NotificationActivationProofLocation::Metadata,
        ] {
            let (builder, calls) = builder(descriptor(location));
            let (mut client, mut peer) = connected_with(&cx, builder, true).await;
            let live = McpRequestCancellation::new();
            let initial = fastmcp_core::OperatorSnapshot::capture(&client).unwrap();
            for (owner, method, parameters) in [
                (
                    ExtensionId::parse("com.example/unknown").unwrap(),
                    NOTIFICATION,
                    json!({}),
                ),
                (id(), METHOD, json!({})),
                (id(), NOTIFICATION, json!({"_meta":[]})),
                (
                    id(),
                    NOTIFICATION,
                    json!({"_meta":{"io.modelcontextprotocol/subscriptionId":{}}}),
                ),
            ] {
                assert_eq!(
                    client
                        .notify_final_extension(&cx, &live, &owner, method, parameters)
                        .await
                        .unwrap_err()
                        .code,
                    McpErrorCode::InvalidParams
                );
            }
            let mut conflicting = json!({});
            match location {
                NotificationActivationProofLocation::Params => {
                    conflicting[PROOF] = json!({"mode":"forged"})
                }
                NotificationActivationProofLocation::Metadata => {
                    conflicting["_meta"] = json!({(PROOF):{"mode":"forged"}})
                }
            }
            assert_eq!(
                client
                    .notify_final_extension(&cx, &live, &id(), NOTIFICATION, conflicting)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::InvalidParams
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "refusals cannot negotiate invented proof"
            );
            for sequence in 0..2 {
                client.notify_final_extension(&cx, &live, &id(), NOTIFICATION, json!({
                    "sequence":sequence,
                    "_meta":{"com.example/note":"retained",
                        "io.modelcontextprotocol/clientCapabilities":{"extensions":{"com.example/forged":{}}}}
                })).await.unwrap();
                let notification = receive(&cx, &mut peer, NOTIFICATION, None).await;
                let parameters = notification.params.unwrap();
                let proof = match location {
                    NotificationActivationProofLocation::Params => &parameters[PROOF],
                    NotificationActivationProofLocation::Metadata => &parameters["_meta"][PROOF],
                };
                assert_eq!(proof, &json!({"mode":"raw"}));
                assert_eq!(parameters["_meta"]["com.example/note"], "retained");
                assert!(
                    parameters["_meta"]
                        .get("io.modelcontextprotocol/protocolVersion")
                        .is_none()
                );
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    sequence + 2,
                    "each message uses a fresh resolver"
                );
                assert_eq!(client.next_id, 2);
                let after = fastmcp_core::OperatorSnapshot::capture(&client).unwrap();
                assert_eq!(after.requests(), initial.requests());
                assert_eq!(after.correlations(), initial.correlations());
            }
            client.close(&cx).unwrap();
        }
    });
}

#[test]
fn memory_extension_unsent_notifications_leave_request_ids_and_controls_untouched() {
    run(|cx| async move {
        let (mut client, mut peer, _) = connected(&cx).await;
        let live = McpRequestCancellation::new();
        let mut first = client
            .execute_final_extension(&cx, &live, &id(), METHOD, json!({}))
            .await
            .unwrap();
        let original = client.executor.pending_records();
        for drop_wait in [false, true] {
            let cancellation = McpRequestCancellation::new();
            {
                let extension_id = id();
                let mut pending = pin!(client.notify_final_extension(
                    &cx,
                    &cancellation,
                    &extension_id,
                    NOTIFICATION,
                    json!({})
                ));
                poll_fn(|task| {
                    assert!(pending.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                if !drop_wait {
                    cancellation.cancel();
                    assert_eq!(
                        pending.await.unwrap_err().code,
                        McpErrorCode::RequestCancelled
                    );
                }
            }
            assert_eq!(client.next_id, 3);
            assert_eq!(client.executor.pending_records(), original);
            assert!(!client.executor.has_external_controls(&cx).unwrap());
        }
        receive(&cx, &mut peer, METHOD, Some(2)).await;
        peer.send_async(&cx, &response(2, json!({"resultType":RESULT,"value":1})))
            .await
            .unwrap();
        extension_result(&cx, &mut client, &mut first)
            .await
            .unwrap();
        client
            .notify_final_extension(&cx, &live, &id(), NOTIFICATION, json!({"published":true}))
            .await
            .unwrap();
        let notification = receive(&cx, &mut peer, NOTIFICATION, None).await;
        assert_eq!(notification.params.unwrap()["published"], true);
        assert_eq!(client.next_id, 3);
        client.close(&cx).unwrap();
    });
}

#[test]
fn memory_extension_notifications_drain_full_ingress_and_preserve_control_priority() {
    run(|cx| async move {
        let (mut client, mut peer, _) = connected(&cx).await;
        let live = McpRequestCancellation::new();
        let mut pending = client
            .execute_final_extension(&cx, &live, &id(), METHOD, json!({}))
            .await
            .unwrap();
        peer.send_async(
            &cx,
            &JsonRpcMessage::Request(JsonRpcRequest::notification(
                "notifications/message",
                Some(json!({"level":"info","data":"queued"})),
            )),
        )
        .await
        .unwrap();
        let mut server = cx
            .spawn(move |peer_cx| async move {
                // Both directions are full. The peer deliberately writes another
                // response before reading the request occupying client capacity.
                peer.send_async(
                    &peer_cx,
                    &response(2, json!({"resultType":RESULT,"value":17})),
                )
                .await
                .unwrap();
                receive(&peer_cx, &mut peer, METHOD, Some(2)).await;
                receive(&peer_cx, &mut peer, NOTIFICATION, None).await;
                peer
            })
            .unwrap();
        client
            .notify_final_extension(&cx, &live, &id(), NOTIFICATION, json!({}))
            .await
            .unwrap();
        assert_eq!(
            extension_result(&cx, &mut client, &mut pending)
                .await
                .unwrap()["value"],
            17
        );
        assert_eq!(client.take_server_notifications().len(), 1);
        let mut peer = server.join(&cx).await.unwrap();

        let abandoned = client
            .execute_final_extension(&cx, &live, &id(), METHOD, json!({}))
            .await
            .unwrap();
        drop(abandoned);
        let mut server = cx
            .spawn(move |peer_cx| async move {
                receive(&peer_cx, &mut peer, METHOD, Some(3)).await;
                let cancel = receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                assert_eq!(cancel.params.unwrap()["requestId"], 3);
                receive(&peer_cx, &mut peer, NOTIFICATION, None).await;
                peer
            })
            .unwrap();
        client
            .notify_final_extension(&cx, &live, &id(), NOTIFICATION, json!({}))
            .await
            .unwrap();
        assert_eq!(client.next_id, 4);
        assert_eq!(client.take_cancellation_events().len(), 1);
        let _peer = server.join(&cx).await.unwrap();
        client.close(&cx).unwrap();
    });
}

#[test]
fn memory_extension_deadlines_and_foreign_handle_refusal_remain_owner_specific() {
    run(|cx| async move {
        let (builder, _) = builder(descriptor(NotificationActivationProofLocation::Params));
        let policy =
            RequestTimeoutPolicy::new(Duration::from_millis(200), Duration::from_secs(1)).unwrap();
        let (mut client, mut peer) =
            connected_with(&cx, builder.timeout_policy(policy).unwrap(), true).await;
        let (mut other, _other_peer, _) = connected(&cx).await;
        let live = McpRequestCancellation::new();
        assert_eq!(
            client
                .execute_final_extension_with_timeout_policy(
                    &cx,
                    &live,
                    &id(),
                    METHOD,
                    json!({}),
                    RequestTimeoutPolicy::new(Duration::from_millis(201), Duration::from_secs(1))
                        .unwrap(),
                )
                .await
                .unwrap_err()
                .code,
            McpErrorCode::InvalidParams
        );
        assert_eq!(client.next_id, 2);
        let mut pending = client
            .execute_final_extension_with_timeout_policy(
                &cx,
                &live,
                &id(),
                METHOD,
                json!({}),
                RequestTimeoutPolicy::new(Duration::from_millis(40), Duration::from_secs(1))
                    .unwrap(),
            )
            .await
            .unwrap();
        receive(&cx, &mut peer, METHOD, Some(2)).await;
        assert_eq!(
            other
                .next_extension_event(&cx, &live, &mut pending)
                .await
                .unwrap_err()
                .code,
            McpErrorCode::InvalidParams
        );
        assert_eq!(
            other.cancel_extension(&cx, &mut pending).unwrap_err().code,
            McpErrorCode::InvalidParams
        );
        assert_eq!(other.next_id, 2);
        let started = Instant::now();
        assert_eq!(
            extension_result(&cx, &mut client, &mut pending)
                .await
                .unwrap_err()
                .code,
            McpErrorCode::RequestCancelled
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!live.is_cancel_requested());
        assert_eq!(
            client.take_cancellation_events()[0].reason,
            crate::ExecutionTerminalReason::IdleTimeout
        );
        assert!(
            client
                .next_extension_event(&cx, &live, &mut pending)
                .await
                .unwrap()
                .is_none()
        );
        client.close(&cx).unwrap();
        other.close(&cx).unwrap();
    });
}
