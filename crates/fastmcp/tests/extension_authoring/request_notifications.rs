//! Typed request-owned producers through the public facade and real transports.

use super::*;
use std::collections::BTreeMap;

use fastmcp_rust::{
    ClientExtensionDiscovery, ClientInfo, ExtensionDescriptor, ExtensionDescriptorRegistry,
    ExtensionDirection, ExtensionFallbackPolicy, ExtensionHttpEraDisposition, ExtensionId,
    ExtensionMethodDescriptor, ExtensionNegotiationError, ExtensionNegotiationResolver,
    ExtensionNotificationDescriptor, ExtensionSettings, ExtensionSettingsSchema,
    McpRequestCancellation, MemoryExtensionEvent, StdioCorrelationCodec, StdioCorrelationDescriptor,
};

const EVENT: &str = "com.example/request-scaled";
const OWNER: &str = "com.example/request-id";

fn producer(calls: Arc<AtomicUsize>) -> ExtensionRegistration {
    builder()
        .typed_request_notification::<ScaleResponse>(EVENT, "request-scaled-v1", OWNER)
        .unwrap()
        .typed_request_sync(
            METHOD, "scale-params-v1", "scale-result-v1",
            move |context: ExtensionContext<'_, Settings>, request: ScaleRequest| {
                calls.fetch_add(1, Ordering::SeqCst);
                let declaration = context.descriptor().request_notification().unwrap();
                assert_eq!(declaration.name(), EVENT);
                assert_eq!(declaration.correlation_metadata_key(), OWNER);
                assert_eq!(declaration.direction(), ExtensionDirection::ServerToClient);
                match request.value {
                    10 => context.notify(&"wrong parameter type")?,
                    11 => context.notify(&json!({"value": 33, "_meta": {OWNER: "forged"}}))?,
                    12 => context.notify(&json!({"value": 36, "padding": "x".repeat(65_536)}))?,
                    value => context.notify(&ScaleResponse { value: value * 3 })?,
                }
                Ok(ScaleResponse { value: request.value * 3 })
            },
        )
        .unwrap()
        .build()
        .unwrap()
}

fn consumer() -> (ExtensionId, ExtensionDescriptorRegistry, ClientExtensionDiscovery) {
    let id = ExtensionId::parse(EXTENSION).unwrap();
    let mut registry = ExtensionDescriptorRegistry::new();
    registry.register(ExtensionDescriptor {
        id: id.clone(),
        client_settings: ExtensionSettingsSchema {
            schema_id: "typed-math-client-v1".into(), codec_id: "client-codec-v1".into(),
        },
        server_settings: ExtensionSettingsSchema {
            schema_id: "typed-math-server-v1".into(), codec_id: "server-codec-v1".into(),
        },
        resolver: ExtensionNegotiationResolver {
            id: "request-notification-resolver-v1".into(), version: 1,
            fallback: ExtensionFallbackPolicy::RejectOneSided,
        },
        method: Some(ExtensionMethodDescriptor {
            name: METHOD.into(), direction: ExtensionDirection::ClientToServer,
            http_era_disposition: Some(ExtensionHttpEraDisposition::ModernExclusive),
            legacy_fallback: false,
        }),
        notification: Some(ExtensionNotificationDescriptor {
            name: EVENT.into(), direction: ExtensionDirection::ServerToClient,
            activation_proof: None,
        }),
        result_discriminator: None,
        routing_headers: vec![],
        stdio_correlation: Some(StdioCorrelationDescriptor {
            metadata_key: OWNER.into(), methods: vec![EVENT.into()],
            direction: ExtensionDirection::ServerToClient, codec: StdioCorrelationCodec::RequestId,
        }),
    }).unwrap();
    let discovery = ClientExtensionDiscovery {
        extensions: BTreeMap::from([(id.clone(), ExtensionSettings::new(json!({"version": 1})).unwrap())]),
    };
    (id, registry, discovery)
}

fn compatible(
    _descriptor: &ExtensionDescriptor,
    client: &ExtensionSettings,
    server: &ExtensionSettings,
) -> Result<ExtensionSettings, ExtensionNegotiationError> {
    assert_eq!(client.as_object().get("version"), server.as_object().get("version"));
    Ok(server.clone())
}

#[test]
fn typed_request_notifications_reach_only_their_live_memory_execution() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 0).build().unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), async {
            let server = modern::ServerBuilder::new("request-notice-producer", "1")
                .extension(producer(calls)).unwrap().try_build().unwrap();
            let (transport, peer) = create_memory_transport_pair_with_capacity(1);
            let mut serving = cx.spawn(move |server_cx| async move {
                server.serve_memory(&server_cx, peer).await
            }).unwrap();
            let (id, registry, discovery) = consumer();
            let mut client = modern::MemoryClient::builder(ClientInfo {
                name: "request-notice-consumer".into(), version: "1".into(),
            }).extension_registry(registry, discovery, || compatible).unwrap()
                .connect(&cx, transport).await.unwrap();
            let cancellation = McpRequestCancellation::new();
            let mut first = client.execute_final_extension(
                &cx, &cancellation, &id, METHOD, json!({"value": 7}),
            ).await.unwrap();
            let mut second = client.execute_final_extension(
                &cx, &cancellation, &id, METHOD, json!({"value": 9}),
            ).await.unwrap();
            for (execution, value) in [(&mut second, 27), (&mut first, 21)] {
                let expected_id = execution.request_id().clone();
                let Some(MemoryExtensionEvent::Notification(notification)) = client
                    .next_extension_event(&cx, &cancellation, execution).await.unwrap()
                else { panic!("the typed notification precedes its own result"); };
                assert_eq!(notification.method, EVENT);
                assert!(notification.id.is_none());
                let params = notification.params.unwrap();
                assert_eq!(params["value"], value);
                assert_eq!(params["_meta"][OWNER], serde_json::to_value(expected_id).unwrap());
                let Some(MemoryExtensionEvent::Result(result)) = client
                    .next_extension_event(&cx, &cancellation, execution).await.unwrap()
                else { panic!("each owner retains its final response"); };
                assert_eq!(result, json!({"value": value}));
                assert!(client.next_extension_event(&cx, &cancellation, execution).await.unwrap().is_none());
            }
            for value in [10, 11, 12] {
                client.request_final_extension(&cx, &cancellation, &id, METHOD, json!({"value": value}))
                    .await.expect_err("invalid typed payload cannot publish a notification");
                assert!(client.take_server_notifications().is_empty());
            }
            assert_eq!(client.request_final_extension(
                &cx, &cancellation, &id, METHOD, json!({"value": 5}),
            ).await.unwrap(), json!({"value": 15}));
            assert!(client.take_server_notifications().is_empty());
            client.close(&cx).unwrap();
            serving.join(&cx).await.unwrap().unwrap();
        }).await.expect("bounded typed notification exchange and cleanup");
    });
    assert_eq!(observed.load(Ordering::SeqCst), 6);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

struct LateNotice<'a> {
    context: ExtensionContext<'a, Settings>,
    refused: Arc<AtomicUsize>,
}

impl Drop for LateNotice<'_> {
    fn drop(&mut self) {
        if self.context.notify(&ScaleResponse { value: 999 }).is_err() {
            self.refused.fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct PendingProducer(Arc<AtomicUsize>);

impl fastmcp_rust::extensions::authoring::ExtensionHandler<ScaleRequest, ScaleResponse, Settings>
    for PendingProducer
{
    fn handle<'a>(
        &'a self,
        context: ExtensionContext<'a, Settings>,
        request: ScaleRequest,
    ) -> fastmcp_rust::BoxFuture<'a, McpResult<ScaleResponse>> {
        Box::pin(async move {
            context.notify(&ScaleResponse { value: request.value * 3 })?;
            if request.value == 7 {
                let _late = LateNotice { context, refused: Arc::clone(&self.0) };
                std::future::pending::<()>().await;
            }
            Ok(ScaleResponse { value: request.value * 3 })
        })
    }
}

#[test]
fn typed_request_notification_cancellation_refuses_late_drop_emission_and_keeps_sibling() {
    let refused = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&refused);
    let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 0).build().unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), async {
            let registration = builder()
                .typed_request_notification::<ScaleResponse>(EVENT, "request-scaled-v1", OWNER).unwrap()
                .typed_request(METHOD, "scale-params-v1", "scale-result-v1", PendingProducer(refused))
                .unwrap().build().unwrap();
            let server = modern::ServerBuilder::new("cancel-request-notice", "1")
                .extension(registration).unwrap().try_build().unwrap();
            let (transport, peer) = create_memory_transport_pair_with_capacity(1);
            let mut serving = cx.spawn(move |server_cx| async move {
                server.serve_memory(&server_cx, peer).await
            }).unwrap();
            let (id, registry, discovery) = consumer();
            let mut client = modern::MemoryClient::builder(ClientInfo {
                name: "cancel-request-notice-client".into(), version: "1".into(),
            }).extension_registry(registry, discovery, || compatible).unwrap()
                .connect(&cx, transport).await.unwrap();
            let cancellation = McpRequestCancellation::new();
            let mut pending = client.execute_final_extension(
                &cx, &cancellation, &id, METHOD, json!({"value": 7}),
            ).await.unwrap();
            assert!(matches!(client.next_extension_event(&cx, &cancellation, &mut pending).await.unwrap(),
                Some(MemoryExtensionEvent::Notification(_))));
            client.cancel_extension(&cx, &mut pending).unwrap();
            assert!(client.next_extension_event(&cx, &cancellation, &mut pending).await.is_err());
            // The next drive commits the independent cancellation control and
            // still completes a fresh sibling through the same connection.
            assert_eq!(client.request_final_extension(
                &cx, &cancellation, &id, METHOD, json!({"value": 5}),
            ).await.unwrap(), json!({"value": 15}));
            assert!(client.take_server_notifications().is_empty());
            client.close(&cx).unwrap();
            serving.join(&cx).await.unwrap().unwrap();
            assert!(cx.checkpoint().is_ok());
        }).await.expect("request cancellation settles its notification producer");
    });
    assert_eq!(observed.load(Ordering::SeqCst), 1, "late destructor emission is refused");
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn typed_request_notification_registration_rejects_other_owners_and_directions() {
    assert!(builder().typed_request_notification::<ScaleResponse>(
        EVENT, "request-scaled-v1", "other.example/request-id",
    ).is_err());
    let registered = builder().typed_request_notification::<ScaleResponse>(
        EVENT, "request-scaled-v1", OWNER,
    ).unwrap();
    assert!(registered.typed_notification_sync(
        NOTIFICATION, "inbound-notice-v1", ACTIVATION,
        |_: &ScaleNotification| Ok(()),
        |_: ExtensionNotificationContext<'_, Settings>, _: ScaleNotification| Ok(()),
    ).is_err(), "one frozen descriptor cannot silently replace its notification direction");
    assert!(builder().typed_request_notification::<ScaleResponse>(EVENT, "request-scaled-v1", OWNER)
        .unwrap().build().is_err(), "a request-owned producer requires a request handler");
    let calls = Arc::new(AtomicUsize::new(0));
    let responses = run_exchange(producer(Arc::clone(&calls)), vec![
        request(1, None, json!(7)),
        request(2, Some(json!({"version": 2})), json!(7)),
    ]);
    assert!(responses.iter().all(|response| response.error.is_some()));
    assert_eq!(calls.load(Ordering::SeqCst), 0, "missing or incompatible negotiation cannot reach the producer");
    let undeclared = builder().typed_request_sync(
        METHOD, "scale-params-v1", "scale-result-v1",
        |context: ExtensionContext<'_, Settings>, request: ScaleRequest| {
            context.notify(&ScaleResponse { value: request.value })?;
            Ok(ScaleResponse { value: request.value })
        },
    ).unwrap().build().unwrap();
    assert!(run_exchange(undeclared, vec![request(1, Some(json!({"version": 1})), json!(7))])
        [0].error.is_some(), "a request handler cannot create a notification declaration at runtime");
}

#[test]
fn typed_request_notifications_preserve_exact_ids_on_native_stdio() {
    use asupersync::net::{TcpListener, TcpStream};
    use fastmcp_rust::AsyncStdioTransport;

    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(0, 0).build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut serving = cx.spawn(move |server_cx| async move {
                let (socket, _) = listener.accept().await.unwrap();
                let (input, output) = socket.into_split();
                modern::ServerBuilder::new("native-request-notices", "1")
                    .extension(producer(Arc::new(AtomicUsize::new(0)))).unwrap()
                    .try_build().unwrap().serve_stdio_io(&server_cx, input, output).await
            }).unwrap();
            let socket = TcpStream::connect(address).await.unwrap();
            let (input, output) = socket.split();
            let mut peer = AsyncStdioTransport::from_io(input, output);
            let ids = [
                RequestId::String("request/opaque".into()),
                serde_json::from_str::<RequestId>("123456789012345678901234567890").unwrap(),
            ];
            for id in ids {
                let JsonRpcMessage::Request(mut outbound) = request(1, Some(json!({"version": 1})), json!(7))
                else { unreachable!() };
                outbound.id = Some(id.clone());
                peer.send_async(&cx, &JsonRpcMessage::Request(outbound)).await.unwrap();
                let JsonRpcMessage::Request(notification) = peer.recv_async(&cx).await.unwrap()
                else { panic!("typed event is emitted before the terminal result"); };
                assert_eq!(notification.method, EVENT);
                assert_eq!(notification.params.unwrap()["_meta"][OWNER], serde_json::to_value(&id).unwrap());
                let JsonRpcMessage::Response(response) = peer.recv_async(&cx).await.unwrap()
                else { panic!("request retains its terminal response"); };
                assert_eq!(response.id, Some(id));
                assert_eq!(response.result.unwrap(), json!({"value": 21}));
            }
            socket.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(matches!(peer.recv_async(&cx).await, Err(TransportError::Closed)));
            serving.join(&cx).await.unwrap().unwrap();
        }).await.expect("native stdio typed events terminate within the caller budget");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}
