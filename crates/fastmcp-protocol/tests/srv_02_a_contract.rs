use std::collections::BTreeMap;

use fastmcp_protocol::{
    DiscoveryCacheHints, SERVER_DISCOVER_METHOD, SERVER_DISCOVER_SUPPORTED_VERSIONS,
    ServerBehavior, ServerBehaviorRegistry, ServerDiscoverCapabilities, ServerDiscoverRequest,
    ServerDiscoverResult, ServerInfo, ServerInstructions,
};
use serde_json::{Value, json};

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
        DiscoveryCacheHints::private_ttl_ms(60_000),
    );

    let request = serde_json::to_value(ServerDiscoverRequest::default()).expect("request encodes");
    let wire = serde_json::to_value(&result).expect("result encodes");

    assert_eq!(SERVER_DISCOVER_METHOD, "server/discover");
    assert_eq!(
        request,
        json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        })
    );
    assert_eq!(wire["resultType"], json!("complete"));
    assert_eq!(
        wire["supportedVersions"],
        json!(SERVER_DISCOVER_SUPPORTED_VERSIONS)
    );
    assert!(wire.get("protocolVersions").is_none());
    assert_eq!(
        wire["_meta"]["io.modelcontextprotocol/serverInfo"],
        json!({"name": "contract-server", "version": "1.0.0"})
    );
    assert_eq!(wire["capabilities"]["tools"]["listChanged"], json!(true));
    assert_eq!(wire["capabilities"]["resources"]["subscribe"], json!(true));
    assert_eq!(wire["capabilities"]["prompts"]["listChanged"], json!(true));
    assert!(wire["capabilities"].get("subscriptions").is_none());
    assert_eq!(
        wire["capabilities"]["extensions"]["io.fastmcp.example"]["enabled"],
        json!(true)
    );
    assert_eq!(wire["ttlMs"], json!(60_000));
    assert_eq!(wire["cacheScope"], json!("private"));
    assert_eq!(
        DiscoveryCacheHints::private_ttl_ms(u64::MAX).ttl_ms(),
        u64::MAX,
        "the typed cache-hint field admits its complete nonnegative wire domain"
    );

    let mut multi_version_peer = wire;
    multi_version_peer["supportedVersions"] = json!(["2024-11-05", "2026-07-28"]);
    let decoded: ServerDiscoverResult = serde_json::from_value(multi_version_peer)
        .expect("final discovery accepts every schema-valid string version array");
    assert_eq!(
        decoded
            .supported_versions()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["2024-11-05", "2026-07-28"],
        "version selection remains the negotiation layer's responsibility"
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
        DiscoveryCacheHints::private_ttl_ms(0),
    );
    let unchanged_before = serde_json::to_vec(&admitted).expect("admitted state encodes");
    let mut planted: Value = serde_json::to_value(&admitted).expect("baseline result encodes");
    planted["resultType"] = json!("input_required");

    let rejection = serde_json::from_value::<ServerDiscoverResult>(planted);

    assert!(
        rejection.is_err(),
        "only the incompatible result-type field changed"
    );
    assert_eq!(
        serde_json::to_vec(&admitted).expect("admitted state still encodes"),
        unchanged_before,
        "rejected wire input cannot mutate an already-admitted result"
    );
}
