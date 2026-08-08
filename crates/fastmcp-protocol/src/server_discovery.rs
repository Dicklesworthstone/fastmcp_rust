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

use crate::{
    FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION_META_KEY, OpenMetadata, ServerInfo,
    protocol_version::FINAL_PROTOCOL_VERSION,
};

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

/// Typed final `params` for a `server/discover` request.
///
/// Final requests always carry the common request metadata. Unknown
/// method-specific members remain inert and round-trip so a newer peer does
/// not become undecodable merely by extending this open object.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ServerDiscoverRequest {
    #[serde(rename = "_meta")]
    metadata: OpenMetadata,
    #[serde(flatten)]
    extras: BTreeMap<String, Value>,
}

impl Default for ServerDiscoverRequest {
    fn default() -> Self {
        let metadata = OpenMetadata::try_from_entries([
            (
                FINAL_PROTOCOL_VERSION_META_KEY.to_owned(),
                Value::String(FINAL_PROTOCOL_VERSION.to_owned()),
            ),
            (
                FINAL_CLIENT_CAPABILITIES_META_KEY.to_owned(),
                Value::Object(serde_json::Map::new()),
            ),
        ])
        .expect("the fixed final discovery request metadata is valid");
        Self {
            metadata,
            extras: BTreeMap::new(),
        }
    }
}

impl ServerDiscoverRequest {
    /// Returns the required request metadata without granting its self-reported
    /// values any authority.
    #[must_use]
    pub fn metadata(&self) -> &OpenMetadata {
        &self.metadata
    }
}

#[derive(Deserialize)]
struct ServerDiscoverRequestWire {
    #[serde(rename = "_meta")]
    metadata: OpenMetadata,
    #[serde(flatten)]
    extras: BTreeMap<String, Value>,
}

impl<'de> Deserialize<'de> for ServerDiscoverRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ServerDiscoverRequestWire::deserialize(deserializer)?;
        let protocol_version = wire.metadata.protocol_version().map_err(D::Error::custom)?;
        let client_capabilities = wire
            .metadata
            .client_capabilities()
            .map_err(D::Error::custom)?;
        if protocol_version != Some(FINAL_PROTOCOL_VERSION) || client_capabilities.is_none() {
            return Err(D::Error::custom(
                ServerDiscoveryError::InvalidRequestMetadata,
            ));
        }
        Ok(Self {
            metadata: wire.metadata,
            extras: wire.extras,
        })
    }
}

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

/// Locally emitted `server/discover` results use the standard complete
/// discriminator. Peer results retain the schema-open string verbatim.
const COMPLETE_DISCOVERY_RESULT_TYPE: &str = "complete";

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

/// Typed capability shape derived from an installed behavior registry.
///
/// `ServerCapabilities` is deliberately an open object in the final schema.
/// Retaining its members as JSON preserves both known capability settings and
/// future peer-defined capabilities without recasting them as local authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerDiscoverCapabilities {
    members: BTreeMap<String, Value>,
}

impl Serialize for ServerDiscoverCapabilities {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.members.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServerDiscoverCapabilities {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let members = BTreeMap::<String, Value>::deserialize(deserializer)?;
        validate_capability_members(&members).map_err(D::Error::custom)?;
        Ok(Self { members })
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
        let mut members = BTreeMap::new();

        if registry.contains(ServerBehavior::LoggingRequestEmitter) {
            members.insert("logging".to_owned(), Value::Object(serde_json::Map::new()));
        }
        if registry.contains(ServerBehavior::CompletionComplete) {
            members.insert(
                "completions".to_owned(),
                Value::Object(serde_json::Map::new()),
            );
        }
        if tools_list {
            let mut tools = serde_json::Map::new();
            if registry.contains(ServerBehavior::ToolsListChangedNotification) {
                tools.insert("listChanged".to_owned(), Value::Bool(true));
            }
            members.insert("tools".to_owned(), Value::Object(tools));
        }
        if resources_list {
            let mut resources = serde_json::Map::new();
            if resources_subscribe {
                resources.insert("subscribe".to_owned(), Value::Bool(true));
            }
            if registry.contains(ServerBehavior::ResourcesListChangedNotification) {
                resources.insert("listChanged".to_owned(), Value::Bool(true));
            }
            members.insert("resources".to_owned(), Value::Object(resources));
        }
        if prompts_list {
            let mut prompts = serde_json::Map::new();
            if registry.contains(ServerBehavior::PromptsListChangedNotification) {
                prompts.insert("listChanged".to_owned(), Value::Bool(true));
            }
            members.insert("prompts".to_owned(), Value::Object(prompts));
        }
        if !extensions.is_empty() {
            members.insert(
                "extensions".to_owned(),
                Value::Object(extensions.into_iter().collect()),
            );
        }

        Ok(Self { members })
    }
}

fn validate_capability_members(
    members: &BTreeMap<String, Value>,
) -> Result<(), ServerDiscoveryError> {
    for capability in ["logging", "completions"] {
        if members
            .get(capability)
            .is_some_and(|value| !value.is_object())
        {
            return Err(ServerDiscoveryError::InvalidCapabilityShape);
        }
    }

    for capability in ["tools", "prompts"] {
        if let Some(Value::Object(settings)) = members.get(capability) {
            if settings
                .get("listChanged")
                .is_some_and(|value| !value.is_boolean())
            {
                return Err(ServerDiscoveryError::InvalidCapabilityShape);
            }
        } else if members.contains_key(capability) {
            return Err(ServerDiscoveryError::InvalidCapabilityShape);
        }
    }

    if let Some(Value::Object(settings)) = members.get("resources") {
        for field in ["listChanged", "subscribe"] {
            if settings.get(field).is_some_and(|value| !value.is_boolean()) {
                return Err(ServerDiscoveryError::InvalidCapabilityShape);
            }
        }
    } else if members.contains_key("resources") {
        return Err(ServerDiscoveryError::InvalidCapabilityShape);
    }

    if let Some(Value::Object(settings)) = members.get("experimental") {
        if settings.values().any(|value| !value.is_object()) {
            return Err(ServerDiscoveryError::InvalidCapabilityShape);
        }
    } else if members.contains_key("experimental") {
        return Err(ServerDiscoveryError::InvalidCapabilityShape);
    }

    if let Some(Value::Object(settings)) = members.get("extensions") {
        let extensions = settings
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        validate_extensions(&extensions)?;
    } else if members.contains_key("extensions") {
        return Err(ServerDiscoveryError::InvalidCapabilityShape);
    }

    Ok(())
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
        if !value.is_object() {
            return Err(ServerDiscoveryError::InvalidCapabilityShape);
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
    #[serde(rename = "resultType")]
    result_type: String,
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
    #[serde(flatten)]
    extras: BTreeMap<String, Value>,
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
            result_type: COMPLETE_DISCOVERY_RESULT_TYPE.to_owned(),
            supported_versions: SERVER_DISCOVER_SUPPORTED_VERSIONS
                .iter()
                .map(|version| (*version).to_owned())
                .collect(),
            capabilities,
            metadata: ServerDiscoverResultMetadata::server_generated(server_info),
            instructions,
            cache_hints,
            extras: BTreeMap::new(),
        }
    }

    /// Returns the protocol versions advertised by this server.
    #[must_use]
    pub fn supported_versions(&self) -> &[String] {
        &self.supported_versions
    }

    /// Returns the schema-open result discriminator received from the peer.
    #[must_use]
    pub fn result_type(&self) -> &str {
        &self.result_type
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
#[serde(rename_all = "camelCase")]
struct ServerDiscoverResultWire {
    #[serde(rename = "resultType")]
    result_type: String,
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
    #[serde(flatten)]
    extras: BTreeMap<String, Value>,
}

impl<'de> Deserialize<'de> for ServerDiscoverResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ServerDiscoverResultWire::deserialize(deserializer)?;
        Ok(Self {
            result_type: wire.result_type,
            supported_versions: wire.supported_versions,
            capabilities: wire.capabilities,
            metadata: wire.metadata,
            instructions: wire.instructions.0,
            cache_hints: DiscoveryCacheHints::from_peer_wire(wire.ttl_ms, wire.cache_scope),
            extras: wire.extras,
        })
    }
}

/// Why a server discovery value could not be safely constructed or admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerDiscoveryError {
    /// The request did not carry the required final request metadata.
    InvalidRequestMetadata,
    /// A known capability field did not use its schema-required object shape.
    InvalidCapabilityShape,
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
            Self::InvalidRequestMetadata => write!(
                formatter,
                "server/discover requires final protocol version and client capabilities metadata"
            ),
            Self::InvalidCapabilityShape => {
                write!(
                    formatter,
                    "server/discover capability has an invalid schema shape"
                )
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
        ServerDiscoverResult, ServerInfo, ServerInstructions,
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
    fn server_discover_accepts_schema_valid_supported_versions() {
        let admitted = ServerDiscoverResult::new(
            fully_installed_capabilities(),
            ServerInfo {
                name: "contract-server".to_owned(),
                version: "1.0.0".to_owned(),
            },
            None,
            DiscoveryCacheHints::private_ttl_ms(0),
        );
        let mut peer_wire: Value =
            serde_json::to_value(&admitted).expect("the admitted result encodes");
        peer_wire["supportedVersions"] = json!(["2024-11-05", "2026-07-28"]);

        let decoded: ServerDiscoverResult = serde_json::from_value(peer_wire)
            .expect("the final schema permits any string version advertisement");
        assert_eq!(
            decoded
                .supported_versions()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["2024-11-05", "2026-07-28"],
            "version selection remains a negotiation-layer concern"
        );
    }

    #[test]
    fn server_discover_round_trips_schema_open_result_type() {
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
        let mut peer_wire: Value =
            serde_json::to_value(&admitted).expect("the admitted result encodes");
        peer_wire["resultType"] = json!("com.example/deferred-discovery");

        let decoded: ServerDiscoverResult = serde_json::from_value(peer_wire.clone())
            .expect("a schema-open discovery resultType is retained");
        assert_eq!(
            decoded.result_type(),
            "com.example/deferred-discovery",
            "the typed API exposes the received open discriminator"
        );
        assert_eq!(
            serde_json::to_value(decoded).expect("the open discriminator re-encodes"),
            peer_wire,
            "the schema-valid open resultType round-trips unchanged"
        );
        assert_eq!(
            serde_json::to_vec(&admitted).expect("the admitted result still encodes"),
            unchanged_before,
            "admitting a separate peer result cannot mutate locally admitted state"
        );
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
        let mut missing_result_type: Value =
            serde_json::to_value(&admitted).expect("the admitted result encodes");
        missing_result_type
            .as_object_mut()
            .expect("the discovery result is an object")
            .remove("resultType");

        assert!(
            serde_json::from_value::<ServerDiscoverResult>(missing_result_type).is_err(),
            "removing only required resultType rejects the final discovery result"
        );
        assert_eq!(
            serde_json::to_vec(&admitted).expect("the admitted result still encodes"),
            unchanged_before,
            "rejecting the one-field variant cannot mutate locally admitted state"
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
