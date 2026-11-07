//! Registered extension admission and real native TLS request coverage.

use super::*;
use fastmcp_protocol::extensions::{
    ClientExtensionDiscovery, ExtensionDescriptor, ExtensionDescriptorRegistry, ExtensionDirection,
    ExtensionFallbackPolicy, ExtensionHttpEraDisposition, ExtensionId, ExtensionMethodDescriptor,
    ExtensionNegotiationError, ExtensionNegotiationResolver, ExtensionSettings,
    ExtensionSettingsSchema,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "native-tls-roots")]
mod tls;

const EXTENSION: &str = "com.example/dpop-echo";
const OTHER_EXTENSION: &str = "com.example/dpop-other";
const METHOD: &str = "example/dpop-echo";
const RESULT: &str = "com.example/dpop-echo-result";
const OTHER_RESULT: &str = "com.example/dpop-other-result";

fn extension_id() -> ExtensionId {
    ExtensionId::parse(EXTENSION).unwrap()
}

fn descriptor() -> ExtensionDescriptor {
    ExtensionDescriptor {
        id: extension_id(),
        client_settings: ExtensionSettingsSchema {
            schema_id: "dpop-echo-client-v1".to_owned(),
            codec_id: "dpop-echo-client-codec-v1".to_owned(),
        },
        server_settings: ExtensionSettingsSchema {
            schema_id: "dpop-echo-server-v1".to_owned(),
            codec_id: "dpop-echo-server-codec-v1".to_owned(),
        },
        resolver: ExtensionNegotiationResolver {
            id: "dpop-echo-compatibility-v1".to_owned(),
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
    // These settings deliberately differ across the two peers. The frozen
    // compatibility resolver, rather than object equality, grants authority.
    if client.as_object().get("format") != server.as_object().get("format")
        || server.as_object().get("capacity").and_then(Value::as_u64) != Some(8)
    {
        return Err(ExtensionNegotiationError::SettingsCompatibilityRejected(
            descriptor.id.to_string(),
        ));
    }
    Ok(client.clone())
}

fn configuration(
    primary: ExtensionDescriptor,
    enabled: bool,
) -> (DpopExtensionConfiguration, Arc<AtomicUsize>) {
    let mut registry = ExtensionDescriptorRegistry::new();
    registry.register(primary).unwrap();
    let mut other = descriptor();
    other.id = ExtensionId::parse(OTHER_EXTENSION).unwrap();
    other.method.as_mut().unwrap().name = "example/dpop-other".to_owned();
    other.result_discriminator = Some(OTHER_RESULT.to_owned());
    registry.register(other).unwrap();
    let mut extensions = BTreeMap::from([(
        ExtensionId::parse(OTHER_EXTENSION).unwrap(),
        ExtensionSettings::new(json!({"format":"echo-v1"})).unwrap(),
    )]);
    if enabled {
        extensions.insert(
            extension_id(),
            ExtensionSettings::new(json!({"format":"echo-v1"})).unwrap(),
        );
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let factory_calls = Arc::clone(&calls);
    let configuration = DpopExtensionConfiguration::new(
        registry,
        ClientExtensionDiscovery { extensions },
        move || {
            factory_calls.fetch_add(1, Ordering::SeqCst);
            compatible
        },
    )
    .unwrap();
    (configuration, calls)
}

#[test]
fn operation_ids_require_distinct_exact_correlation_keys() {
    for (discovery, operation) in [
        (RequestId::Number(1), RequestId::Number(1)),
        (RequestId::Number(1), RequestId::Integer("1e0".to_owned())),
        (RequestId::Integer("1.5".to_owned()), RequestId::Number(2)),
        (RequestId::Number(1), RequestId::Integer("2.5".to_owned())),
    ] {
        assert!(matches!(
            DpopExtensionOperation::new(discovery, operation, extension_id(), METHOD, json!({})),
            Err(ManagedCoreError::InvalidRequest)
        ));
    }
    assert!(DpopExtensionOperation::new(
        RequestId::Number(1),
        RequestId::String("1".to_owned()),
        extension_id(),
        METHOD,
        json!({}),
    )
    .is_ok());
}

#[test]
fn operation_parameters_require_an_object_with_object_metadata() {
    for parameters in [Value::Null, json!([]), json!(1), json!({"_meta":[]})] {
        assert!(matches!(
            DpopExtensionOperation::new(
                RequestId::Number(1),
                RequestId::Number(2),
                extension_id(),
                METHOD,
                parameters,
            ),
            Err(ManagedCoreError::InvalidRequest)
        ));
    }
    assert!(DpopExtensionOperation::new(
        RequestId::Number(1),
        RequestId::Number(2),
        extension_id(),
        METHOD,
        json!({"_meta":{"progressToken":"owned", "com.example/note":"retained"}}),
    )
    .is_ok());
}

#[test]
fn configuration_requires_a_registered_owner_without_running_discovery() {
    let (configuration, calls) = configuration(descriptor(), true);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(configuration);
    let discovery = ClientExtensionDiscovery {
        extensions: BTreeMap::from([(
            extension_id(),
            ExtensionSettings::new(json!({"format":"echo-v1"})).unwrap(),
        )]),
    };
    assert!(DpopExtensionConfiguration::new(
        ExtensionDescriptorRegistry::new(),
        discovery,
        || compatible,
    )
    .is_err());
}
