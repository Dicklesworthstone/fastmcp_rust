//! A real typed extension producer and the shipped generic HTTP consumer.

use std::collections::BTreeMap;

use super::*;
use fastmcp_rust::{
    CanonicalHttpUrl, ClientExtensionDiscovery, ExtensionDescriptor, ExtensionDescriptorRegistry,
    ExtensionDirection, ExtensionFallbackPolicy, ExtensionHttpEraDisposition, ExtensionId,
    ExtensionMethodDescriptor, ExtensionNegotiationError, ExtensionNegotiationResolver,
    ExtensionSettings, ExtensionSettingsSchema,
};

fn client_configuration() -> (
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
            notification: None,
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
