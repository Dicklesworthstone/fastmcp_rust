//! Typed `server/discover` vocabulary for the final MCP discovery surface.
//!
//! The registry is deliberately declarative: it records only handlers and
//! notification delivery paths that the surrounding server has actually
//! installed. Discovery capabilities are derived from that immutable record,
//! so a wire claim cannot accidentally advertise an unregistered behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::SerializeMap};
use serde_json::Value;

use crate::{ServerInfo, protocol_version::FINAL_PROTOCOL_VERSION};

/// The exact JSON-RPC method for final server discovery.
pub const SERVER_DISCOVER_METHOD: &str = "server/discover";

/// The exact protocol-version list advertised by this final-only surface.
pub const SERVER_DISCOVER_SUPPORTED_VERSIONS: &[&str] = &[FINAL_PROTOCOL_VERSION];

/// Maximum UTF-8 bytes permitted for server-provided discovery instructions.
pub const MAX_SERVER_INSTRUCTIONS_BYTES: usize = 16 * 1024;

/// Maximum number of enabled extension settings in one discovery result.
pub const MAX_DISCOVERY_EXTENSION_SETTINGS: usize = 64;

/// Maximum UTF-8 bytes in an enabled extension setting name.
pub const MAX_DISCOVERY_EXTENSION_NAME_BYTES: usize = 256;

/// Maximum JSON bytes in an enabled extension setting value.
pub const MAX_DISCOVERY_EXTENSION_VALUE_BYTES: usize = 16 * 1024;

/// Reserved result-metadata key that identifies the responding server.
pub const SERVER_DISCOVER_SERVER_INFO_META_KEY: &str = "io.modelcontextprotocol/serverInfo";

/// The typed empty `params` object for a `server/discover` request.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerDiscoverRequest {}

/// A server behavior whose installation can be advertised through discovery.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ServerBehavior {
    /// The deprecated `logging/request` emitter is installed.
    LoggingRequestEmitter,
    /// The `completion/complete` dispatch target is installed.
    CompletionComplete,
    /// The `tools/list` dispatch target is installed.
    ToolsList,
    /// The `notifications/tools/list_changed` producer is installed.
    ToolsListChangedNotification,
    /// The `resources/list` dispatch target is installed.
    ResourcesList,
    /// The `notifications/resources/list_changed` producer is installed.
    ResourcesListChangedNotification,
    /// The `resources/subscribe` dispatch target is installed.
    ResourcesSubscribe,
    /// The subscription listener used by resource subscriptions is installed.
    SubscriptionsListen,
    /// The resource-update delivery path is installed.
    ResourceUpdateDelivery,
    /// The `prompts/list` dispatch target is installed.
    PromptsList,
    /// The `notifications/prompts/list_changed` producer is installed.
    PromptsListChangedNotification,
}

/// Immutable registry of server behavior actually installed by the runtime.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServerBehaviorRegistry {
    installed: BTreeSet<ServerBehavior>,
}

impl ServerBehaviorRegistry {
    /// Creates a registry from the installed behaviors.
    #[must_use]
    pub fn from_behaviors(behaviors: impl IntoIterator<Item = ServerBehavior>) -> Self {
        Self {
            installed: behaviors.into_iter().collect(),
        }
    }

    /// Returns whether a behavior has been installed.
    #[must_use]
    pub fn contains(&self, behavior: ServerBehavior) -> bool {
        self.installed.contains(&behavior)
    }
}

/// A validated server instruction string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerInstructions(String);

impl ServerInstructions {
    /// Validates and retains discovery instructions.
    pub fn new(value: impl Into<String>) -> Result<Self, ServerInstructionError> {
        let value = value.into();
        if value.len() > MAX_SERVER_INSTRUCTIONS_BYTES {
            return Err(ServerInstructionError::TooLarge {
                actual: value.len(),
                maximum: MAX_SERVER_INSTRUCTIONS_BYTES,
            });
        }
        Ok(Self(value))
    }

    /// Returns the validated instruction text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for ServerInstructions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ServerInstructions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Why a server instruction string was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerInstructionError {
    /// The UTF-8 instruction string exceeded the fixed discovery bound.
    TooLarge {
        /// Observed UTF-8 byte length.
        actual: usize,
        /// Maximum accepted UTF-8 byte length.
        maximum: usize,
    },
}

impl fmt::Display for ServerInstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "server instructions are {actual} bytes; maximum is {maximum}"
                )
            }
        }
    }
}

impl Error for ServerInstructionError {}

/// A strict cache scope received from or emitted on the discovery wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum DiscoveryCacheScope {
    Public,
    Private,
}

impl<'de> Deserialize<'de> for DiscoveryCacheScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "public" => Ok(Self::Public),
            "private" => Ok(Self::Private),
            _ => Err(D::Error::custom("cacheScope must be `public` or `private`")),
        }
    }
}

/// Required final caching hints for a `server/discover` result.
///
/// Safe local construction is intentionally limited to the private scope.
/// A public cache scope is peer provenance admitted only while decoding an
/// already-received wire result; it is not a general authority grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DiscoveryCacheHints {
    #[serde(rename = "ttlMs")]
    ttl_ms: u64,
    #[serde(rename = "cacheScope")]
    scope: DiscoveryCacheScope,
}

impl DiscoveryCacheHints {
    /// Creates a server-generated, private cache hint with a nonnegative TTL
    /// in milliseconds.
    #[must_use]
    pub const fn private_ttl_ms(ttl_ms: u64) -> Self {
        Self {
            ttl_ms,
            scope: DiscoveryCacheScope::Private,
        }
    }

    /// Returns the cache TTL in milliseconds.
    #[must_use]
    pub const fn ttl_ms(self) -> u64 {
        self.ttl_ms
    }

    /// Returns whether this was an admitted public peer cache hint.
    #[must_use]
    pub const fn is_public(self) -> bool {
        matches!(self.scope, DiscoveryCacheScope::Public)
    }

    const fn from_peer_wire(ttl_ms: u64, scope: DiscoveryCacheScope) -> Self {
        Self { ttl_ms, scope }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EmptyCapability {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListCapability {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    list_changed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourcesCapability {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    subscribe: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    list_changed: bool,
}

/// Typed capability shape derived from an installed behavior registry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerDiscoverCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    logging: Option<EmptyCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completions: Option<EmptyCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<ListCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resources: Option<ResourcesCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prompts: Option<ListCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extensions: Option<BTreeMap<String, Value>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServerDiscoverCapabilitiesWire {
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    logging: Option<EmptyCapability>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    completions: Option<EmptyCapability>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    tools: Option<ListCapability>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    resources: Option<ResourcesCapability>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    prompts: Option<ListCapability>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    extensions: Option<BTreeMap<String, Value>>,
}

fn deserialize_optional_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl<'de> Deserialize<'de> for ServerDiscoverCapabilities {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ServerDiscoverCapabilitiesWire::deserialize(deserializer)?;
        if let Some(extensions) = wire.extensions.as_ref() {
            if extensions.is_empty() {
                return Err(D::Error::custom(
                    ServerDiscoveryError::EmptyExtensionSettings,
                ));
            }
            validate_extensions(extensions).map_err(D::Error::custom)?;
        }
        Ok(Self {
            logging: wire.logging,
            completions: wire.completions,
            tools: wire.tools,
            resources: wire.resources,
            prompts: wire.prompts,
            extensions: wire.extensions,
        })
    }
}

impl ServerDiscoverCapabilities {
    /// Derives discovery capabilities from installed behavior and extensions.
    pub fn from_registry(
        registry: &ServerBehaviorRegistry,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ServerDiscoveryError> {
        validate_extensions(&extensions)?;

        let tools_list = registry.contains(ServerBehavior::ToolsList);
        let resources_list = registry.contains(ServerBehavior::ResourcesList);
        let prompts_list = registry.contains(ServerBehavior::PromptsList);
        let resources_subscribe = registry.contains(ServerBehavior::ResourcesSubscribe)
            && registry.contains(ServerBehavior::SubscriptionsListen)
            && registry.contains(ServerBehavior::ResourceUpdateDelivery);

        Ok(Self {
            logging: registry
                .contains(ServerBehavior::LoggingRequestEmitter)
                .then_some(EmptyCapability {}),
            completions: registry
                .contains(ServerBehavior::CompletionComplete)
                .then_some(EmptyCapability {}),
            tools: tools_list.then_some(ListCapability {
                list_changed: registry.contains(ServerBehavior::ToolsListChangedNotification),
            }),
            resources: resources_list.then_some(ResourcesCapability {
                subscribe: resources_subscribe,
                list_changed: registry.contains(ServerBehavior::ResourcesListChangedNotification),
            }),
            prompts: prompts_list.then_some(ListCapability {
                list_changed: registry.contains(ServerBehavior::PromptsListChangedNotification),
            }),
            extensions: (!extensions.is_empty()).then_some(extensions),
        })
    }
}

fn validate_extensions(extensions: &BTreeMap<String, Value>) -> Result<(), ServerDiscoveryError> {
    if extensions.len() > MAX_DISCOVERY_EXTENSION_SETTINGS {
        return Err(ServerDiscoveryError::TooManyExtensionSettings {
            actual: extensions.len(),
            maximum: MAX_DISCOVERY_EXTENSION_SETTINGS,
        });
    }

    for (name, value) in extensions {
        if name.is_empty() || name.len() > MAX_DISCOVERY_EXTENSION_NAME_BYTES {
            return Err(ServerDiscoveryError::InvalidExtensionName {
                length: name.len(),
                maximum: MAX_DISCOVERY_EXTENSION_NAME_BYTES,
            });
        }
        let encoded_len = serde_json::to_vec(value)
            .map_err(|_| ServerDiscoveryError::ExtensionValueEncoding)?
            .len();
        if encoded_len > MAX_DISCOVERY_EXTENSION_VALUE_BYTES {
            return Err(ServerDiscoveryError::ExtensionValueTooLarge {
                actual: encoded_len,
                maximum: MAX_DISCOVERY_EXTENSION_VALUE_BYTES,
            });
        }
    }
    Ok(())
}

/// Result metadata carried by `server/discover`.
///
/// `serverInfo` belongs in the common `_meta` object in final MCP, not in the
/// method-specific discovery payload. Other admitted metadata is preserved as
/// inert result metadata instead of being reinterpreted as a capability.
#[derive(Clone, Debug, Default)]
struct ServerDiscoverResultMetadata {
    server_info: Option<ServerInfo>,
    extras: BTreeMap<String, Value>,
}

impl ServerDiscoverResultMetadata {
    fn server_generated(server_info: ServerInfo) -> Self {
        Self {
            server_info: Some(server_info),
            extras: BTreeMap::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.server_info.is_none() && self.extras.is_empty()
    }
}

impl Serialize for ServerDiscoverResultMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(
            self.extras.len() + usize::from(self.server_info.is_some()),
        ))?;
        if let Some(server_info) = &self.server_info {
            map.serialize_entry(SERVER_DISCOVER_SERVER_INFO_META_KEY, server_info)?;
        }
        for (name, value) in &self.extras {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ServerDiscoverResultMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut members = BTreeMap::<String, Value>::deserialize(deserializer)?;
        let server_info = members
            .remove(SERVER_DISCOVER_SERVER_INFO_META_KEY)
            .map(serde_json::from_value)
            .transpose()
            .map_err(D::Error::custom)?;
        Ok(Self {
            server_info,
            extras: members,
        })
    }
}

/// A presence-aware optional instruction field.
///
/// Serde's ordinary `Option<T>` accepts explicit `null`; the final discovery
/// vocabulary permits absence but rejects `null` and every non-string value.
#[derive(Default)]
struct OptionalServerInstructions(Option<ServerInstructions>);

impl<'de> Deserialize<'de> for OptionalServerInstructions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        ServerInstructions::deserialize(deserializer).map(|instructions| Self(Some(instructions)))
    }
}

/// Typed `server/discover` result whose wire vocabulary is fixed to final MCP.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerDiscoverResult {
    #[serde(rename = "supportedVersions")]
    supported_versions: Vec<String>,
    capabilities: ServerDiscoverCapabilities,
    #[serde(
        rename = "_meta",
        skip_serializing_if = "ServerDiscoverResultMetadata::is_empty"
    )]
    metadata: ServerDiscoverResultMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    instructions: Option<ServerInstructions>,
    #[serde(flatten)]
    cache_hints: DiscoveryCacheHints,
}

impl ServerDiscoverResult {
    /// Creates a final discovery response with its exact supported-version
    /// list, server identity in `_meta`, and required cache hints.
    #[must_use]
    pub fn new(
        capabilities: ServerDiscoverCapabilities,
        server_info: ServerInfo,
        instructions: Option<ServerInstructions>,
        cache_hints: DiscoveryCacheHints,
    ) -> Self {
        Self {
            supported_versions: SERVER_DISCOVER_SUPPORTED_VERSIONS
                .iter()
                .map(|version| (*version).to_owned())
                .collect(),
            capabilities,
            metadata: ServerDiscoverResultMetadata::server_generated(server_info),
            instructions,
            cache_hints,
        }
    }

    /// Returns the exact final protocol versions advertised on the wire.
    #[must_use]
    pub fn supported_versions(&self) -> &[String] {
        &self.supported_versions
    }

    /// Returns the derived capability shape.
    #[must_use]
    pub fn capabilities(&self) -> &ServerDiscoverCapabilities {
        &self.capabilities
    }

    /// Returns the self-reported server identity when the peer supplied one.
    #[must_use]
    pub fn server_info(&self) -> Option<&ServerInfo> {
        self.metadata.server_info.as_ref()
    }

    /// Returns optional server guidance without assigning it any authority.
    #[must_use]
    pub fn instructions(&self) -> Option<&ServerInstructions> {
        self.instructions.as_ref()
    }

    /// Returns the required cache hints attached to this discovery result.
    #[must_use]
    pub const fn cache_hints(&self) -> DiscoveryCacheHints {
        self.cache_hints
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServerDiscoverResultWire {
    #[serde(rename = "supportedVersions")]
    supported_versions: Vec<String>,
    capabilities: ServerDiscoverCapabilities,
    #[serde(rename = "_meta", default)]
    metadata: ServerDiscoverResultMetadata,
    #[serde(default)]
    instructions: OptionalServerInstructions,
    #[serde(rename = "ttlMs")]
    ttl_ms: u64,
    #[serde(rename = "cacheScope")]
    cache_scope: DiscoveryCacheScope,
}

impl<'de> Deserialize<'de> for ServerDiscoverResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ServerDiscoverResultWire::deserialize(deserializer)?;
        let expected: Vec<String> = SERVER_DISCOVER_SUPPORTED_VERSIONS
            .iter()
            .map(|version| (*version).to_owned())
            .collect();
        if wire.supported_versions != expected {
            return Err(D::Error::custom(
                ServerDiscoveryError::UnsupportedProtocolVersions,
            ));
        }
        Ok(Self {
            supported_versions: wire.supported_versions,
            capabilities: wire.capabilities,
            metadata: wire.metadata,
            instructions: wire.instructions.0,
            cache_hints: DiscoveryCacheHints::from_peer_wire(wire.ttl_ms, wire.cache_scope),
        })
    }
}

/// Why a server discovery value could not be safely constructed or admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerDiscoveryError {
    /// The supplied result advertised a version list other than the exact final list.
    UnsupportedProtocolVersions,
    /// The `capabilities.extensions` field was present without an enabled extension.
    EmptyExtensionSettings,
    /// The registry attempted to advertise more extension settings than allowed.
    TooManyExtensionSettings {
        /// Observed extension setting count.
        actual: usize,
        /// Maximum allowed extension setting count.
        maximum: usize,
    },
    /// An extension setting name was empty or exceeded its fixed bound.
    InvalidExtensionName {
        /// Observed UTF-8 byte length.
        length: usize,
        /// Maximum allowed UTF-8 byte length.
        maximum: usize,
    },
    /// An extension setting value exceeded its exact JSON byte bound.
    ExtensionValueTooLarge {
        /// Observed encoded JSON byte length.
        actual: usize,
        /// Maximum allowed encoded JSON byte length.
        maximum: usize,
    },
    /// An extension setting value could not be encoded as JSON.
    ExtensionValueEncoding,
}

impl fmt::Display for ServerDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProtocolVersions => write!(
                formatter,
                "server/discover must advertise exactly {SERVER_DISCOVER_SUPPORTED_VERSIONS:?}"
            ),
            Self::EmptyExtensionSettings => {
                write!(formatter, "empty capabilities.extensions must be omitted")
            }
            Self::TooManyExtensionSettings { actual, maximum } => {
                write!(
                    formatter,
                    "{actual} extension settings exceed the maximum {maximum}"
                )
            }
            Self::InvalidExtensionName { length, maximum } => {
                write!(
                    formatter,
                    "extension name is {length} bytes; maximum is {maximum}"
                )
            }
            Self::ExtensionValueTooLarge { actual, maximum } => write!(
                formatter,
                "extension setting is {actual} JSON bytes; maximum is {maximum}"
            ),
            Self::ExtensionValueEncoding => {
                write!(formatter, "extension setting could not be encoded")
            }
        }
    }
}

impl Error for ServerDiscoveryError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::{Value, json};

    use crate::{
        DiscoveryCacheHints, SERVER_DISCOVER_METHOD, SERVER_DISCOVER_SUPPORTED_VERSIONS,
        ServerBehavior, ServerBehaviorRegistry, ServerDiscoverCapabilities, ServerDiscoverRequest,
        ServerDiscoverResult, ServerDiscoveryError, ServerInfo, ServerInstructions,
    };

    fn fully_installed_capabilities() -> ServerDiscoverCapabilities {
        ServerDiscoverCapabilities::from_registry(
            &ServerBehaviorRegistry::from_behaviors([
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
            ]),
            BTreeMap::from([("io.fastmcp.example".to_owned(), json!({"enabled": true}))]),
        )
        .expect("the bounded installed behavior registry is discoverable")
    }

    #[test]
    fn srv_02_b_positive() {
        let result = ServerDiscoverResult::new(
            fully_installed_capabilities(),
            ServerInfo {
                name: "contract-server".to_owned(),
                version: "1.0.0".to_owned(),
            },
            Some(ServerInstructions::new("").expect("empty guidance is present guidance")),
            DiscoveryCacheHints::private_ttl_ms(60_000),
        );

        let request = serde_json::to_value(ServerDiscoverRequest::default())
            .expect("the typed request encodes through the public API");
        let wire =
            serde_json::to_value(&result).expect("the typed result encodes through the public API");

        assert_eq!(SERVER_DISCOVER_METHOD, "server/discover");
        assert_eq!(request, json!({}));
        assert_eq!(
            wire["supportedVersions"],
            json!(SERVER_DISCOVER_SUPPORTED_VERSIONS)
        );
        assert!(wire.get("protocolVersions").is_none());
        assert!(wire.get("serverInfo").is_none());
        assert!(wire.get("cacheHints").is_none());
        assert_eq!(
            wire["_meta"]["io.modelcontextprotocol/serverInfo"],
            json!({"name": "contract-server", "version": "1.0.0"})
        );
        assert_eq!(wire["instructions"], json!(""));
        assert_eq!(wire["ttlMs"], json!(60_000));
        assert_eq!(wire["cacheScope"], json!("private"));
        assert_eq!(wire["capabilities"]["tools"]["listChanged"], json!(true));
        assert_eq!(wire["capabilities"]["resources"]["subscribe"], json!(true));
        assert_eq!(
            wire["capabilities"]["resources"]["listChanged"],
            json!(true)
        );
        assert_eq!(wire["capabilities"]["prompts"]["listChanged"], json!(true));
        assert!(wire["capabilities"].get("subscriptions").is_none());
        assert_eq!(
            wire["capabilities"]["extensions"]["io.fastmcp.example"]["enabled"],
            json!(true)
        );

        let decoded: ServerDiscoverResult = serde_json::from_value(wire)
            .expect("the final server/discover vocabulary decodes deterministically");
        assert_eq!(
            decoded
                .supported_versions()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["2026-07-28"],
            "only the final protocol version is advertised"
        );
        assert_eq!(
            decoded
                .server_info()
                .map(|server_info| server_info.name.as_str()),
            Some("contract-server")
        );
        assert_eq!(
            decoded.instructions().map(ServerInstructions::as_str),
            Some("")
        );
        assert_eq!(decoded.cache_hints().ttl_ms(), 60_000);
        assert!(!decoded.cache_hints().is_public());
    }

    #[test]
    fn srv_02_b_planted_negative() {
        let admitted = ServerDiscoverResult::new(
            fully_installed_capabilities(),
            ServerInfo {
                name: "contract-server".to_owned(),
                version: "1.0.0".to_owned(),
            },
            None,
            DiscoveryCacheHints::private_ttl_ms(0),
        );
        let unchanged_before =
            serde_json::to_vec(&admitted).expect("the admitted result has a stable wire image");
        let mut planted: Value =
            serde_json::to_value(&admitted).expect("the admitted result encodes");
        planted["supportedVersions"] = json!(["2024-11-05"]);

        let rejection = serde_json::from_value::<ServerDiscoverResult>(planted)
            .expect_err("only the forbidden supported-version dimension changed");
        assert_eq!(
            rejection.to_string(),
            ServerDiscoveryError::UnsupportedProtocolVersions.to_string(),
            "the typed version validator reports one deterministic refusal"
        );
        assert_eq!(
            serde_json::to_vec(&admitted).expect("the admitted result still encodes"),
            unchanged_before,
            "rejected peer input cannot mutate the named admitted result state"
        );
    }

    #[test]
    fn server_discover_instructions_preserve_presence_and_reject_null() {
        let absent = ServerDiscoverResult::new(
            fully_installed_capabilities(),
            ServerInfo {
                name: "contract-server".to_owned(),
                version: "1.0.0".to_owned(),
            },
            None,
            DiscoveryCacheHints::private_ttl_ms(0),
        );
        let absent_wire = serde_json::to_value(&absent).expect("absent instructions encode");
        assert!(absent_wire.get("instructions").is_none());

        let mut explicit_null = absent_wire.clone();
        explicit_null["instructions"] = Value::Null;
        assert!(
            serde_json::from_value::<ServerDiscoverResult>(explicit_null).is_err(),
            "explicit null is not interchangeable with absent instructions"
        );
        assert_eq!(
            serde_json::to_value(&absent).expect("the admitted result remains unchanged"),
            absent_wire,
            "the rejected instruction value cannot mutate the admitted result"
        );
    }
}
