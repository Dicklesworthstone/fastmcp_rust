//! Typed `server/discover` vocabulary for the final MCP discovery surface.
//!
//! The registry is deliberately declarative: it records only handlers and
//! notification delivery paths that the surrounding server has actually
//! installed. Discovery capabilities are derived from that immutable record,
//! so a wire claim cannot accidentally advertise an unregistered behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
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

/// Cache directives scoped exclusively to the `cacheHints` discovery field.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscoveryCacheHints {
    max_age_seconds: u32,
}

impl DiscoveryCacheHints {
    /// Creates a discovery cache directive with the supplied nonnegative TTL.
    #[must_use]
    pub const fn with_max_age_seconds(max_age_seconds: u32) -> Self {
        Self { max_age_seconds }
    }

    /// Returns the cache TTL in seconds.
    #[must_use]
    pub const fn max_age_seconds(self) -> u32 {
        self.max_age_seconds
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

/// Typed `server/discover` result whose version list is fixed to final MCP.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerDiscoverResult {
    protocol_versions: Vec<String>,
    capabilities: ServerDiscoverCapabilities,
    server_info: ServerInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    instructions: Option<ServerInstructions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_hints: Option<DiscoveryCacheHints>,
}

impl ServerDiscoverResult {
    /// Creates the final discovery response with its exact supported versions.
    #[must_use]
    pub fn new(
        capabilities: ServerDiscoverCapabilities,
        server_info: ServerInfo,
        instructions: Option<ServerInstructions>,
        cache_hints: Option<DiscoveryCacheHints>,
    ) -> Self {
        Self {
            protocol_versions: SERVER_DISCOVER_SUPPORTED_VERSIONS
                .iter()
                .map(|version| (*version).to_owned())
                .collect(),
            capabilities,
            server_info,
            instructions,
            cache_hints,
        }
    }

    /// Returns the exact final protocol versions advertised on the wire.
    #[must_use]
    pub fn protocol_versions(&self) -> &[String] {
        &self.protocol_versions
    }

    /// Returns the derived capability shape.
    #[must_use]
    pub fn capabilities(&self) -> &ServerDiscoverCapabilities {
        &self.capabilities
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServerDiscoverResultWire {
    protocol_versions: Vec<String>,
    capabilities: ServerDiscoverCapabilities,
    server_info: ServerInfo,
    instructions: Option<ServerInstructions>,
    cache_hints: Option<DiscoveryCacheHints>,
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
        if wire.protocol_versions != expected {
            return Err(D::Error::custom(
                ServerDiscoveryError::UnsupportedProtocolVersions,
            ));
        }
        Ok(Self {
            protocol_versions: wire.protocol_versions,
            capabilities: wire.capabilities,
            server_info: wire.server_info,
            instructions: wire.instructions,
            cache_hints: wire.cache_hints,
        })
    }
}

/// Why a server discovery value could not be safely constructed or admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerDiscoveryError {
    /// The supplied result advertised a version list other than the exact final list.
    UnsupportedProtocolVersions,
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
