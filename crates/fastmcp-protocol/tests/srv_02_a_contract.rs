use std::collections::BTreeMap;

use fastmcp_protocol::{
    DiscoveryCacheHints, ServerBehavior, ServerBehaviorRegistry, ServerDiscoverCapabilities,
    ServerDiscoverRequest, ServerDiscoverResult, ServerInfo, ServerInstructions,
    SERVER_DISCOVER_METHOD, SERVER_DISCOVER_SUPPORTED_VERSIONS,
};
use serde_json::{json, Value};

#[test]
fn srv_02_a_positive() {
    let registry = ServerBehaviorRegistry::from_behaviors([
        ServerBehavior::LoggingRequestEmitter,
        ServerBehavior::CompletionComplete,
        ServerBehavior::ToolsList,
        ServerBehavior::ToolsListChangedNotification,
        ServerBehavior::ResourcesList,
        ServerBehavior::ResourcesListChangedNotification,
        ServerBehavior::ResourcesSubscribe,
        ServerBehavior::SubscriptionsListen,
        ServerBehavior::ResourceUpdateDelivery,
        ServerBehavior::PromptsList,
        ServerBehavior::PromptsListChangedNotification,
    ]);
    let capabilities = ServerDiscoverCapabilities::from_registry(
        &registry,
        BTreeMap::from([("io.fastmcp.example".to_owned(), json!({"enabled": true}))]),
    )
    .expect("bounded installed extension is discoverable");
    let result = ServerDiscoverResult::new(
        capabilities,
        ServerInfo {
            name: "contract-server".to_owned(),
            version: "1.0.0".to_owned(),
        },
        Some(ServerInstructions::new("Use the installed tools.").expect("bounded instructions")),
        Some(DiscoveryCacheHints::with_max_age_seconds(60)),
    );

    let request = serde_json::to_value(ServerDiscoverRequest::default()).expect("request encodes");
    let wire = serde_json::to_value(&result).expect("result encodes");

    assert_eq!(SERVER_DISCOVER_METHOD, "server/discover");
    assert_eq!(request, json!({}));
    assert_eq!(
        wire["protocolVersions"],
        json!(SERVER_DISCOVER_SUPPORTED_VERSIONS)
    );
    assert_eq!(wire["capabilities"]["tools"]["listChanged"], json!(true));
    assert_eq!(wire["capabilities"]["resources"]["subscribe"], json!(true));
    assert_eq!(wire["capabilities"]["prompts"]["listChanged"], json!(true));
    assert!(wire["capabilities"].get("subscriptions").is_none());
    assert_eq!(
        wire["capabilities"]["extensions"]["io.fastmcp.example"]["enabled"],
        json!(true)
    );
    assert_eq!(wire["cacheHints"]["maxAgeSeconds"], json!(60));
    assert_eq!(
        DiscoveryCacheHints::with_max_age_seconds(u32::MAX).max_age_seconds(),
        u32::MAX,
        "the typed cache-hint field admits its complete nonnegative wire domain"
    );
}

#[test]
fn srv_02_a_planted_negative() {
    let capabilities = ServerDiscoverCapabilities::from_registry(
        &ServerBehaviorRegistry::from_behaviors([ServerBehavior::ToolsList]),
        BTreeMap::new(),
    )
    .expect("empty extension registry is valid");
    let admitted = ServerDiscoverResult::new(
        capabilities,
        ServerInfo {
            name: "contract-server".to_owned(),
            version: "1.0.0".to_owned(),
        },
        None,
        None,
    );
    let unchanged_before = serde_json::to_vec(&admitted).expect("admitted state encodes");
    let mut planted: Value = serde_json::to_value(&admitted).expect("baseline result encodes");
    planted["protocolVersions"] = json!(["2024-11-05"]);

    let rejection = serde_json::from_value::<ServerDiscoverResult>(planted);

    assert!(
        rejection.is_err(),
        "only the forbidden version field changed"
    );
    assert_eq!(
        serde_json::to_vec(&admitted).expect("admitted state still encodes"),
        unchanged_before,
        "rejected wire input cannot mutate an already-admitted result"
    );
}
