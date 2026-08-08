//! Frozen, runtime-neutral extension negotiation and request admission.
//!
//! This module owns no handler, transport, authorization, or client/server
//! runtime state. It does bind a developer's explicit local opt-in and both
//! peers' current settings to bounded, modern-only request admission.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fastmcp_core::sha256_bounded;
use serde_json::{Map, Value};

use crate::methods::{final_2026_07_28_method, legacy_2024_11_05_method};
use crate::protocol_policy::ProtocolEra;

/// Maximum descriptors retained by one registry.
pub const MAX_EXTENSION_DESCRIPTORS: usize = 128;
/// Maximum bytes in an extension identifier.
pub const MAX_EXTENSION_ID_BYTES: usize = 512;
/// Maximum bytes in one canonical descriptor-registry digest subject.
pub const MAX_EXTENSION_REGISTRY_CANONICAL_BYTES: usize = 256 * 1024;
/// Maximum extension settings entries preserved at the generic boundary.
pub const MAX_EXTENSION_SETTINGS_ENTRIES: usize = 128;
/// Maximum UTF-8 bytes in one extension settings key.
pub const MAX_EXTENSION_SETTINGS_KEY_BYTES: usize = 512;
/// Maximum canonical JSON bytes in one extension settings value.
pub const MAX_EXTENSION_SETTINGS_VALUE_BYTES: usize = 16 * 1024;
/// Maximum nesting depth admitted in a generic extension settings value.
pub const MAX_EXTENSION_SETTINGS_NESTING: usize = 32;
/// Maximum UTF-8 bytes in an extension-owned method or notification name.
pub const MAX_EXTENSION_MEMBER_NAME_BYTES: usize = 512;
/// Maximum extension-owned routing headers registered by one descriptor.
pub const MAX_EXTENSION_ROUTING_HEADERS: usize = 32;
/// Maximum UTF-8 bytes in an extension-owned routing header name.
pub const MAX_EXTENSION_ROUTING_HEADER_BYTES: usize = 256;
/// Maximum notification method names owned by one stdio correlation descriptor.
pub const MAX_STDIO_CORRELATION_METHODS: usize = 32;

/// Official Tasks extension identifier.
pub const OFFICIAL_TASKS_EXTENSION_ID: &str = "io.modelcontextprotocol/tasks";
/// Official Tasks empty-settings schema identity for both peers.
pub const OFFICIAL_TASKS_EMPTY_SETTINGS_SCHEMA_ID: &str = "tasks-2026-07-28-empty-object-v1";
/// Official Tasks empty-settings codec identity for both peers.
pub const OFFICIAL_TASKS_EMPTY_SETTINGS_CODEC_ID: &str = "tasks-2026-07-28-empty-object-v1";
/// Official Tasks client-to-server request methods.
pub const OFFICIAL_TASKS_METHODS: [&str; 3] = ["tasks/get", "tasks/update", "tasks/cancel"];
/// Official Tasks server-to-client notification method.
pub const OFFICIAL_TASKS_NOTIFICATION: &str = "notifications/tasks";
/// Official Tasks `tools/call` result discriminator.
pub const OFFICIAL_TASKS_RESULT_DISCRIMINATOR: &str = "task";

/// A validated extension identifier, preserving its exact wire spelling.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExtensionId(String);

impl ExtensionId {
    /// Validates the final metadata-key prefix/name grammar.
    pub fn parse(value: impl Into<String>) -> Result<Self, ExtensionRegistryError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_EXTENSION_ID_BYTES {
            return Err(ExtensionRegistryError::InvalidIdentifier(value));
        }
        let Some((prefix, name)) = value.split_once('/') else {
            return Err(ExtensionRegistryError::InvalidIdentifier(value));
        };
        if value.matches('/').count() != 1 || !valid_prefix(prefix) || !valid_name(name) {
            return Err(ExtensionRegistryError::InvalidIdentifier(value));
        }
        Ok(Self(value))
    }

    /// Returns the byte-preserved identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ExtensionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn valid_prefix(prefix: &str) -> bool {
    prefix.split('.').all(|label| {
        !label.is_empty()
            && label.as_bytes()[0].is_ascii_alphabetic()
            && label
                .as_bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn valid_name(name: &str) -> bool {
    name.is_empty()
        || (name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .as_bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
}

/// One extension's generic JSON-object settings.
#[derive(Clone, Debug, PartialEq)]
pub struct ExtensionSettings(Map<String, Value>);

impl ExtensionSettings {
    /// Admits exactly a JSON object, including an empty object.
    pub fn new(value: Value) -> Result<Self, ExtensionRegistryError> {
        let Value::Object(map) = value else {
            return Err(ExtensionRegistryError::SettingsNotObject);
        };
        validate_settings_map(&map)?;
        Ok(Self(map))
    }

    /// Returns the preserved generic object.
    #[must_use]
    pub const fn as_object(&self) -> &Map<String, Value> {
        &self.0
    }

    /// Returns the generic object as a JSON value without decoding it.
    #[must_use]
    pub fn into_value(self) -> Value {
        Value::Object(self.0)
    }

    /// Decodes this descriptor-scoped object through a caller-selected typed codec.
    pub fn decode<T>(&self) -> Result<T, ExtensionRegistryError>
    where
        T: serde::de::DeserializeOwned,
    {
        serde_json::from_value(Value::Object(self.0.clone()))
            .map_err(|_| ExtensionRegistryError::SettingsCodecRejected)
    }
}

/// Returns the sole settings object admitted by the official Tasks extension.
#[must_use]
pub fn official_tasks_empty_settings() -> ExtensionSettings {
    ExtensionSettings(Map::new())
}

fn validate_settings_map(map: &Map<String, Value>) -> Result<(), ExtensionRegistryError> {
    if map.len() > MAX_EXTENSION_SETTINGS_ENTRIES {
        return Err(ExtensionRegistryError::SettingsTooManyEntries);
    }
    for (key, value) in map {
        if key.len() > MAX_EXTENSION_SETTINGS_KEY_BYTES {
            return Err(ExtensionRegistryError::SettingsKeyTooLong);
        }
        validate_settings_value(value, 0)?;
        let encoded =
            serde_json::to_vec(value).map_err(|_| ExtensionRegistryError::SettingsTooLarge)?;
        if encoded.len() > MAX_EXTENSION_SETTINGS_VALUE_BYTES {
            return Err(ExtensionRegistryError::SettingsTooLarge);
        }
    }
    Ok(())
}

fn validate_settings_value(value: &Value, depth: usize) -> Result<(), ExtensionRegistryError> {
    if depth > MAX_EXTENSION_SETTINGS_NESTING {
        return Err(ExtensionRegistryError::SettingsTooDeep);
    }
    match value {
        Value::Array(values) => {
            for value in values {
                validate_settings_value(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            if values.len() > MAX_EXTENSION_SETTINGS_ENTRIES {
                return Err(ExtensionRegistryError::SettingsTooManyEntries);
            }
            for (key, value) in values {
                if key.len() > MAX_EXTENSION_SETTINGS_KEY_BYTES {
                    return Err(ExtensionRegistryError::SettingsKeyTooLong);
                }
                validate_settings_value(value, depth + 1)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

/// Public discovery input for one enabled local extension.
#[derive(Clone, Debug, PartialEq)]
pub struct ExtensionDiscovery {
    /// Registered extension identifier.
    pub id: ExtensionId,
    /// Exact generic settings advertised by this peer.
    pub settings: ExtensionSettings,
}

/// Public client discovery input; no client runtime is stored here.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClientExtensionDiscovery {
    /// Enabled client extensions keyed by their IDs.
    pub extensions: BTreeMap<ExtensionId, ExtensionSettings>,
}

/// Public server discovery input; no server runtime is stored here.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ServerExtensionDiscovery {
    /// Enabled server extensions keyed by their IDs.
    pub extensions: BTreeMap<ExtensionId, ExtensionSettings>,
}

/// Direction of a registered RPC name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionDirection {
    /// A client sends a request or notification to a server.
    ClientToServer,
    /// A server sends a request or notification to a client.
    ServerToClient,
}

/// Frozen HTTP-era classification for client-to-server extension methods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionHttpEraDisposition {
    /// The method is audited absent from the exact legacy adapter.
    ModernExclusive,
    /// Method text alone cannot select an era.
    EraAmbiguous,
}

/// Declares the fallback expected by a descriptor's resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionFallbackPolicy {
    /// Both peers must advertise compatible settings.
    RejectOneSided,
    /// A missing client advertisement selects the descriptor's inactive fallback.
    ServerInactiveFallback,
    /// A missing server advertisement selects the descriptor's inactive fallback.
    ClientInactiveFallback,
}

/// Stable, total settings compatibility resolver metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionNegotiationResolver {
    /// Stable resolver identifier included in the registry digest.
    pub id: String,
    /// Stable resolver version included in the registry digest.
    pub version: u32,
    /// One-sided behavior selected by this resolver.
    pub fallback: ExtensionFallbackPolicy,
}

/// Stable schema and typed-codec identity, not an executable runtime codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionSettingsSchema {
    /// Stable schema identity.
    pub schema_id: String,
    /// Stable typed codec identity.
    pub codec_id: String,
}

/// A registered method and its frozen era/fallback declarations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionMethodDescriptor {
    /// Exact JSON-RPC method name.
    pub name: String,
    /// Message direction.
    pub direction: ExtensionDirection,
    /// Required only for client-to-server HTTP methods.
    pub http_era_disposition: Option<ExtensionHttpEraDisposition>,
    /// Whether exact legacy fallback is declared; exact legacy excludes extensions, so this must
    /// remain false.
    pub legacy_fallback: bool,
}

/// A registered notification name and direction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionNotificationDescriptor {
    /// Exact notification name.
    pub name: String,
    /// Message direction.
    pub direction: ExtensionDirection,
}

/// A routing-header name owned by an extension descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionRoutingHeaderDescriptor {
    /// Exact header name.
    pub name: String,
}

/// A stdio notification-correlation metadata key owned by an extension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdioCorrelationDescriptor {
    /// Exact extension-owned metadata key.
    pub metadata_key: String,
    /// Notifications permitted to use the key.
    pub methods: Vec<String>,
    /// Direction required for every named notification.
    pub direction: ExtensionDirection,
}

/// One immutable extension descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionDescriptor {
    /// Descriptor owner.
    pub id: ExtensionId,
    /// Stable client settings schema and codec identity.
    pub client_settings: ExtensionSettingsSchema,
    /// Stable server settings schema and codec identity.
    pub server_settings: ExtensionSettingsSchema,
    /// Stable compatibility resolver identity and fallback.
    pub resolver: ExtensionNegotiationResolver,
    /// Registered request method, when this extension defines one.
    pub method: Option<ExtensionMethodDescriptor>,
    /// Registered notification, when this extension defines one.
    pub notification: Option<ExtensionNotificationDescriptor>,
    /// Registered result discriminator, when this extension defines one.
    pub result_discriminator: Option<String>,
    /// Routing headers this descriptor owns.
    pub routing_headers: Vec<ExtensionRoutingHeaderDescriptor>,
    /// Optional stdio correlation metadata descriptor.
    pub stdio_correlation: Option<StdioCorrelationDescriptor>,
}

/// Returns the validated identifier for the official Tasks extension.
#[must_use]
pub fn official_tasks_extension_id() -> ExtensionId {
    ExtensionId::parse(OFFICIAL_TASKS_EXTENSION_ID)
        .expect("the fixed official Tasks identifier satisfies the extension grammar")
}

/// Returns the complete official Tasks descriptor.
///
/// It owns exactly `tasks/get`, `tasks/update`, `tasks/cancel`,
/// `notifications/tasks`, and the `tools/call` result discriminator `task`.
/// Tasks settings are exactly the empty JSON object;
/// [`ExtensionDescriptorRegistry::negotiate`] enforces that invariant for the
/// two peer advertisements and the effective settings chosen by its resolver.
#[must_use]
pub fn official_tasks_descriptor() -> ExtensionDescriptor {
    ExtensionDescriptor {
        id: official_tasks_extension_id(),
        client_settings: ExtensionSettingsSchema {
            schema_id: OFFICIAL_TASKS_EMPTY_SETTINGS_SCHEMA_ID.to_owned(),
            codec_id: OFFICIAL_TASKS_EMPTY_SETTINGS_CODEC_ID.to_owned(),
        },
        server_settings: ExtensionSettingsSchema {
            schema_id: OFFICIAL_TASKS_EMPTY_SETTINGS_SCHEMA_ID.to_owned(),
            codec_id: OFFICIAL_TASKS_EMPTY_SETTINGS_CODEC_ID.to_owned(),
        },
        resolver: ExtensionNegotiationResolver {
            id: OFFICIAL_TASKS_EMPTY_SETTINGS_SCHEMA_ID.to_owned(),
            version: 1,
            fallback: ExtensionFallbackPolicy::RejectOneSided,
        },
        method: Some(official_tasks_method(OFFICIAL_TASKS_METHODS[0])),
        notification: Some(ExtensionNotificationDescriptor {
            name: OFFICIAL_TASKS_NOTIFICATION.to_owned(),
            direction: ExtensionDirection::ServerToClient,
        }),
        result_discriminator: Some(OFFICIAL_TASKS_RESULT_DISCRIMINATOR.to_owned()),
        routing_headers: Vec::new(),
        stdio_correlation: None,
    }
}

/// Registers the complete official Tasks surface atomically.
///
/// The resulting descriptor owns exactly the official Tasks request methods,
/// its one server notification, and its `tools/call` result discriminator.
/// Registration alone does not activate the extension; normal local enablement
/// and bilateral negotiation still apply.
pub fn register_official_tasks_extension(
    registry: &mut ExtensionDescriptorRegistry,
) -> Result<ExtensionId, ExtensionRegistryError> {
    let id = official_tasks_extension_id();
    let mut candidate = registry.clone();
    candidate.register(official_tasks_descriptor())?;
    for name in OFFICIAL_TASKS_METHODS.into_iter().skip(1) {
        candidate.register_method(&id, official_tasks_method(name))?;
    }
    *registry = candidate;
    Ok(id)
}

fn official_tasks_method(name: &str) -> ExtensionMethodDescriptor {
    ExtensionMethodDescriptor {
        name: name.to_owned(),
        direction: ExtensionDirection::ClientToServer,
        http_era_disposition: Some(ExtensionHttpEraDisposition::ModernExclusive),
        legacy_fallback: false,
    }
}

/// Immutable receipt returned by [`ExtensionDescriptorRegistry::freeze`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionRegistryReceipt {
    digest: [u8; 32],
    descriptor_count: usize,
}

impl ExtensionRegistryReceipt {
    /// Returns the domain-separated descriptor-registry digest bytes.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the number of frozen descriptors.
    #[must_use]
    pub const fn descriptor_count(&self) -> usize {
        self.descriptor_count
    }
}

/// Stable registry-validation diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtensionRegistryError {
    /// The identifier did not satisfy the mandatory prefix/name grammar.
    InvalidIdentifier(String),
    /// The identifier used a reserved official second DNS label.
    ReservedNamespace(String),
    /// Generic settings were not a JSON object.
    SettingsNotObject,
    /// Typed settings decoding rejected the otherwise preserved object.
    SettingsCodecRejected,
    /// Generic settings exceeded the fixed number of retained members.
    SettingsTooManyEntries,
    /// A generic settings key exceeded its fixed byte limit.
    SettingsKeyTooLong,
    /// A generic settings value exceeded its fixed encoded-byte limit.
    SettingsTooLarge,
    /// A generic settings value exceeded its fixed nesting limit.
    SettingsTooDeep,
    /// A descriptor omitted a required stable owner value.
    MissingOwner(&'static str),
    /// A descriptor ID was registered twice.
    DuplicateExtensionId(String),
    /// A method was added to an extension that is not registered.
    UnregisteredExtensionId(String),
    /// A named field already belongs to a different descriptor.
    OwnershipCollision { field: &'static str, value: String },
    /// A client-to-server method omitted its frozen era disposition.
    MissingHttpEraDisposition(String),
    /// Legacy fallback contradicts the frozen HTTP-era disposition.
    LegacyFallbackContradiction(String),
    /// A descriptor attempted to claim a legacy/shared core method.
    CoreMethodCollision(String),
    /// A descriptor attempted to claim a legacy/shared core notification.
    CoreNotificationCollision(String),
    /// A descriptor attempted to claim a final-core result discriminator.
    CoreResultDiscriminatorCollision(String),
    /// A descriptor member exceeded its bounded wire-name limit.
    MemberNameTooLong { field: &'static str, value: String },
    /// A descriptor claimed the same local wire name in incompatible roles.
    LocalOwnershipCollision { field: &'static str, value: String },
    /// Registration occurred after the immutable registry was frozen.
    Frozen,
    /// The canonical digest subject exceeded its bounded limit.
    DigestTooLarge,
}

impl fmt::Display for ExtensionRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier(value) => {
                write!(formatter, "invalid extension identifier: {value}")
            }
            Self::ReservedNamespace(value) => {
                write!(formatter, "reserved extension namespace: {value}")
            }
            Self::SettingsNotObject => {
                formatter.write_str("extension settings must be a JSON object")
            }
            Self::SettingsCodecRejected => {
                formatter.write_str("extension settings codec rejected object")
            }
            Self::SettingsTooManyEntries => {
                formatter.write_str("extension settings exceed their entry limit")
            }
            Self::SettingsKeyTooLong => {
                formatter.write_str("extension settings key exceeds its byte limit")
            }
            Self::SettingsTooLarge => {
                formatter.write_str("extension settings value exceeds its byte limit")
            }
            Self::SettingsTooDeep => {
                formatter.write_str("extension settings exceed their nesting limit")
            }
            Self::MissingOwner(field) => {
                write!(formatter, "missing extension descriptor owner: {field}")
            }
            Self::DuplicateExtensionId(value) => {
                write!(formatter, "duplicate extension identifier: {value}")
            }
            Self::UnregisteredExtensionId(value) => {
                write!(formatter, "unregistered extension identifier: {value}")
            }
            Self::OwnershipCollision { field, value } => {
                write!(formatter, "extension {field} ownership collision: {value}")
            }
            Self::MissingHttpEraDisposition(value) => write!(
                formatter,
                "client-to-server method has no HTTP-era disposition: {value}"
            ),
            Self::LegacyFallbackContradiction(value) => write!(
                formatter,
                "legacy fallback contradicts HTTP-era disposition: {value}"
            ),
            Self::CoreMethodCollision(value) => write!(
                formatter,
                "extension method collides with legacy/shared core method: {value}"
            ),
            Self::CoreNotificationCollision(value) => write!(
                formatter,
                "extension notification collides with legacy/shared core notification: {value}"
            ),
            Self::CoreResultDiscriminatorCollision(value) => write!(
                formatter,
                "extension result discriminator collides with final-core result: {value}"
            ),
            Self::MemberNameTooLong { field, value } => write!(
                formatter,
                "extension {field} exceeds its byte limit: {value}"
            ),
            Self::LocalOwnershipCollision { field, value } => write!(
                formatter,
                "extension {field} has incompatible local ownership: {value}"
            ),
            Self::Frozen => formatter.write_str("extension descriptor registry is frozen"),
            Self::DigestTooLarge => {
                formatter.write_str("extension descriptor registry digest subject exceeds bound")
            }
        }
    }
}

impl std::error::Error for ExtensionRegistryError {}

/// Local feature and runtime opt-in state for the registered descriptors.
///
/// The default is deliberately empty: registering an extension does not enable
/// it for any request.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExtensionLocalEnablement {
    compiled: BTreeSet<ExtensionId>,
    runtime: BTreeSet<ExtensionId>,
}

impl ExtensionLocalEnablement {
    /// Enables one descriptor at both the compile-feature and runtime layers.
    pub fn enable(&mut self, id: ExtensionId) {
        self.compiled.insert(id.clone());
        self.runtime.insert(id);
    }

    /// Records whether the local build includes a descriptor's compile feature.
    pub fn set_compiled(&mut self, id: ExtensionId, enabled: bool) {
        set_enabled(&mut self.compiled, id, enabled);
    }

    /// Records whether the current local runtime enables a descriptor.
    pub fn set_runtime(&mut self, id: ExtensionId, enabled: bool) {
        set_enabled(&mut self.runtime, id, enabled);
    }

    /// Returns whether both local enablement gates are satisfied.
    #[must_use]
    pub fn is_enabled(&self, id: &ExtensionId) -> bool {
        self.compiled.contains(id) && self.runtime.contains(id)
    }

    fn configured_ids(&self) -> impl Iterator<Item = &ExtensionId> {
        self.compiled.iter().chain(self.runtime.iter())
    }
}

fn set_enabled(set: &mut BTreeSet<ExtensionId>, id: ExtensionId, enabled: bool) {
    if enabled {
        set.insert(id);
    } else {
        set.remove(&id);
    }
}

/// The peer side that omitted an otherwise locally enabled extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionPeer {
    /// The current message omitted client extension settings.
    Client,
    /// Local server discovery omitted server extension settings.
    Server,
}

/// A non-activating extension outcome retained for diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionInactiveReason {
    /// The compile-time feature or runtime opt-in is absent.
    LocallyDisabled,
    /// Neither peer advertised the descriptor on this current exchange.
    NotAdvertised,
    /// The registered fallback was selected after the client omitted support.
    ServerInactiveFallback,
    /// The registered fallback was selected after the server omitted support.
    ClientInactiveFallback,
}

/// Normalized typed settings produced by a descriptor's compatibility resolver.
///
/// Generic registry code retains client and server settings independently and
/// never compares their JSON objects for equality. A typed resolver receives
/// both objects and returns this one normalized, bounded value.
#[derive(Clone, Debug, PartialEq)]
pub struct EffectiveExtensionSettings {
    settings: ExtensionSettings,
    fingerprint: [u8; 32],
}

impl EffectiveExtensionSettings {
    /// Returns the typed-resolver's normalized settings object.
    #[must_use]
    pub const fn settings(&self) -> &ExtensionSettings {
        &self.settings
    }

    /// Returns the stable fingerprint bound to the descriptor and effective settings.
    #[must_use]
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
}

/// An enabled extension after the current-message bilateral negotiation.
#[derive(Clone, Debug, PartialEq)]
pub struct NegotiatedExtension {
    id: ExtensionId,
    effective_settings: EffectiveExtensionSettings,
}

impl NegotiatedExtension {
    /// Returns the registered descriptor identifier.
    #[must_use]
    pub const fn id(&self) -> &ExtensionId {
        &self.id
    }

    /// Returns the compatibility resolver's normalized effective settings.
    #[must_use]
    pub const fn effective_settings(&self) -> &EffectiveExtensionSettings {
        &self.effective_settings
    }
}

/// Frozen per-request extension state derived from both peers' current settings.
#[derive(Clone, Debug, PartialEq)]
pub struct NegotiatedExtensionSet {
    registry_receipt: ExtensionRegistryReceipt,
    protocol_era: ProtocolEra,
    active: BTreeMap<ExtensionId, NegotiatedExtension>,
    inactive: BTreeMap<ExtensionId, ExtensionInactiveReason>,
    unknown_client: BTreeMap<ExtensionId, ExtensionSettings>,
    unknown_server: BTreeMap<ExtensionId, ExtensionSettings>,
}

impl NegotiatedExtensionSet {
    /// Returns the registry receipt that this set is bound to.
    #[must_use]
    pub const fn registry_receipt(&self) -> &ExtensionRegistryReceipt {
        &self.registry_receipt
    }

    /// Returns the exact modern protocol era that produced this request state.
    #[must_use]
    pub const fn protocol_era(&self) -> ProtocolEra {
        self.protocol_era
    }

    /// Returns a negotiated extension when it is active for this exchange.
    #[must_use]
    pub fn active(&self, id: &ExtensionId) -> Option<&NegotiatedExtension> {
        self.active.get(id)
    }

    /// Returns the recorded non-activating outcome for a registered descriptor.
    #[must_use]
    pub fn inactive_reason(&self, id: &ExtensionId) -> Option<ExtensionInactiveReason> {
        self.inactive.get(id).copied()
    }

    /// Returns enabled descriptors in deterministic identifier order.
    #[must_use]
    pub fn active_extensions(&self) -> impl ExactSizeIterator<Item = &NegotiatedExtension> {
        self.active.values()
    }

    /// Returns unknown current-message client settings preserved only for diagnostics.
    #[must_use]
    pub const fn unknown_client_extensions(&self) -> &BTreeMap<ExtensionId, ExtensionSettings> {
        &self.unknown_client
    }

    /// Returns unknown server discovery settings preserved only for diagnostics.
    #[must_use]
    pub const fn unknown_server_extensions(&self) -> &BTreeMap<ExtensionId, ExtensionSettings> {
        &self.unknown_server
    }
}

/// Error returned while deriving a per-request bilateral extension set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtensionNegotiationError {
    /// Extensions are excluded from exact MCP 2024-11-05 negotiation.
    LegacyProtocolExcluded,
    /// Descriptor registration must be frozen before negotiation.
    RegistryNotFrozen,
    /// A local feature/runtime configuration referenced an unregistered descriptor.
    UnregisteredLocalEnablement(String),
    /// A discovery map exceeded the generic retained-entry limit.
    DiscoveryTooManyExtensions(ExtensionPeer),
    /// Only one peer advertised a locally enabled descriptor without its matching fallback.
    OneSidedSupport { id: String, missing: ExtensionPeer },
    /// The selected typed resolver rejected both independently decoded settings objects.
    SettingsCompatibilityRejected(String),
    /// The normalized settings object could not be fingerprinted within its bound.
    EffectiveSettingsTooLarge(String),
}

impl fmt::Display for ExtensionNegotiationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyProtocolExcluded => {
                formatter.write_str("extensions are excluded from exact MCP 2024-11-05")
            }
            Self::RegistryNotFrozen => {
                formatter.write_str("extension descriptor registry is not frozen")
            }
            Self::UnregisteredLocalEnablement(id) => {
                write!(
                    formatter,
                    "local extension enablement has no descriptor: {id}"
                )
            }
            Self::DiscoveryTooManyExtensions(peer) => {
                write!(
                    formatter,
                    "{peer:?} extension discovery exceeds its entry limit"
                )
            }
            Self::OneSidedSupport { id, missing } => {
                write!(formatter, "extension {id} is missing {missing:?} support")
            }
            Self::SettingsCompatibilityRejected(id) => {
                write!(formatter, "extension settings are incompatible: {id}")
            }
            Self::EffectiveSettingsTooLarge(id) => {
                write!(
                    formatter,
                    "effective extension settings exceed their bound: {id}"
                )
            }
        }
    }
}

impl std::error::Error for ExtensionNegotiationError {}

/// A typed compatibility resolver selected by a frozen descriptor ID/version.
///
/// This protocol-only seam deliberately accepts no server or client runtime
/// object. Implementations decode the two settings objects independently,
/// check compatibility, and return a normalized effective object.
pub trait ExtensionSettingsCompatibilityResolver {
    /// Resolves both current settings objects into normalized effective settings.
    fn resolve(
        &mut self,
        descriptor: &ExtensionDescriptor,
        client: &ExtensionSettings,
        server: &ExtensionSettings,
    ) -> Result<ExtensionSettings, ExtensionNegotiationError>;
}

impl<F> ExtensionSettingsCompatibilityResolver for F
where
    F: FnMut(
        &ExtensionDescriptor,
        &ExtensionSettings,
        &ExtensionSettings,
    ) -> Result<ExtensionSettings, ExtensionNegotiationError>,
{
    fn resolve(
        &mut self,
        descriptor: &ExtensionDescriptor,
        client: &ExtensionSettings,
        server: &ExtensionSettings,
    ) -> Result<ExtensionSettings, ExtensionNegotiationError> {
        self(descriptor, client, server)
    }
}

/// Direction-sensitive extension dispatch failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtensionDispatchError {
    /// Extensions are excluded from an exact MCP 2024-11-05 request.
    LegacyProtocolExcluded,
    /// The request era does not match the immutable era that negotiated this set.
    ProtocolEraMismatch {
        /// The exact era that created this set.
        negotiated: ProtocolEra,
        /// The exact era attached to the request being admitted.
        request: ProtocolEra,
    },
    /// Dispatch used a registry other than the frozen registry that negotiated the set.
    RegistryReceiptMismatch,
    /// The named extension was not activated by developer opt-in and bilateral negotiation.
    InactiveCapability(String),
    /// The active capability does not own the named request member.
    CapabilityDoesNotOwn {
        /// Active extension capability identifier.
        capability: String,
        /// Registered member category.
        field: &'static str,
        /// Request-supplied member spelling.
        value: String,
    },
    /// The caller supplied an unbounded member name.
    NameTooLong(String),
    /// No active extension owns the requested member in this direction.
    NoActiveOwner { field: &'static str, value: String },
    /// An owner exists but is declared in the opposite direction.
    DirectionMismatch {
        field: &'static str,
        value: String,
        expected: ExtensionDirection,
        actual: ExtensionDirection,
    },
    /// A registry invariant was violated by more than one active owner.
    AmbiguousActiveOwner { field: &'static str, value: String },
}

impl fmt::Display for ExtensionDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyProtocolExcluded => {
                formatter.write_str("extensions are excluded from exact MCP 2024-11-05")
            }
            Self::ProtocolEraMismatch {
                negotiated,
                request,
            } => write!(
                formatter,
                "extension request era {request:?} does not match negotiated era {negotiated:?}"
            ),
            Self::RegistryReceiptMismatch => {
                formatter.write_str("extension dispatch registry does not match negotiation")
            }
            Self::InactiveCapability(capability) => {
                write!(
                    formatter,
                    "extension capability is not active: {capability}"
                )
            }
            Self::CapabilityDoesNotOwn {
                capability,
                field,
                value,
            } => write!(
                formatter,
                "extension capability {capability} does not own {field}: {value}"
            ),
            Self::NameTooLong(value) => {
                write!(
                    formatter,
                    "extension dispatch name exceeds its byte limit: {value}"
                )
            }
            Self::NoActiveOwner { field, value } => {
                write!(formatter, "no active extension owns {field}: {value}")
            }
            Self::DirectionMismatch {
                field,
                value,
                expected,
                actual,
            } => write!(
                formatter,
                "extension {field} has direction {actual:?}, not {expected:?}: {value}"
            ),
            Self::AmbiguousActiveOwner { field, value } => {
                write!(formatter, "multiple active extensions own {field}: {value}")
            }
        }
    }
}

impl std::error::Error for ExtensionDispatchError {}

/// Acyclic protocol-only descriptor registry.
#[derive(Clone, Debug, Default)]
pub struct ExtensionDescriptorRegistry {
    descriptors: BTreeMap<ExtensionId, ExtensionDescriptor>,
    additional_methods: BTreeMap<ExtensionId, BTreeMap<String, ExtensionMethodDescriptor>>,
    receipt: Option<ExtensionRegistryReceipt>,
}

impl ExtensionDescriptorRegistry {
    /// Builds an empty registry; extensions are disabled until a descriptor is registered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one descriptor after validating all descriptor-local and cross-owner rules.
    pub fn register(
        &mut self,
        descriptor: ExtensionDescriptor,
    ) -> Result<(), ExtensionRegistryError> {
        if self.receipt.is_some() {
            return Err(ExtensionRegistryError::Frozen);
        }
        if self.descriptors.len() >= MAX_EXTENSION_DESCRIPTORS {
            return Err(ExtensionRegistryError::DigestTooLarge);
        }
        validate_descriptor(&descriptor)?;
        if self.descriptors.contains_key(&descriptor.id) {
            return Err(ExtensionRegistryError::DuplicateExtensionId(
                descriptor.id.to_string(),
            ));
        }
        for existing in self.descriptors.values() {
            ensure_no_cross_owner_collision(existing, &descriptor)?;
        }
        if let Some(method) = &descriptor.method {
            for (existing_id, methods) in &self.additional_methods {
                if methods.contains_key(&method.name) {
                    return Err(ExtensionRegistryError::OwnershipCollision {
                        field: "method",
                        value: method.name.clone(),
                    });
                }
                if self
                    .descriptors
                    .get(existing_id)
                    .and_then(|existing| existing.notification.as_ref())
                    .is_some_and(|notification| notification.name == method.name)
                {
                    return Err(ExtensionRegistryError::OwnershipCollision {
                        field: "method/notification",
                        value: method.name.clone(),
                    });
                }
            }
        }
        if let Some(notification) = &descriptor.notification {
            for methods in self.additional_methods.values() {
                if methods.contains_key(&notification.name) {
                    return Err(ExtensionRegistryError::OwnershipCollision {
                        field: "method/notification",
                        value: notification.name.clone(),
                    });
                }
            }
        }
        self.descriptors.insert(descriptor.id.clone(), descriptor);
        Ok(())
    }

    /// Adds another request method to an already registered extension descriptor.
    ///
    /// One extension can own more than one request method. The extension's
    /// settings, resolver, notification, and result discriminator stay on the
    /// original descriptor so every additional method shares the same negotiated
    /// capability and frozen receipt.
    pub fn register_method(
        &mut self,
        id: &ExtensionId,
        method: ExtensionMethodDescriptor,
    ) -> Result<(), ExtensionRegistryError> {
        if self.receipt.is_some() {
            return Err(ExtensionRegistryError::Frozen);
        }
        let Some(descriptor) = self.descriptors.get(id) else {
            return Err(ExtensionRegistryError::UnregisteredExtensionId(
                id.to_string(),
            ));
        };
        validate_extension_method(&method)?;
        if descriptor
            .method
            .as_ref()
            .is_some_and(|registered| registered.name == method.name)
            || self
                .additional_methods
                .get(id)
                .is_some_and(|methods| methods.contains_key(&method.name))
        {
            return Err(ExtensionRegistryError::LocalOwnershipCollision {
                field: "method",
                value: method.name,
            });
        }
        if descriptor
            .notification
            .as_ref()
            .is_some_and(|notification| notification.name == method.name)
        {
            return Err(ExtensionRegistryError::LocalOwnershipCollision {
                field: "method/notification",
                value: method.name,
            });
        }
        for (existing_id, existing) in &self.descriptors {
            if existing_id == id {
                continue;
            }
            if existing
                .method
                .as_ref()
                .is_some_and(|registered| registered.name == method.name)
                || self
                    .additional_methods
                    .get(existing_id)
                    .is_some_and(|methods| methods.contains_key(&method.name))
            {
                return Err(ExtensionRegistryError::OwnershipCollision {
                    field: "method",
                    value: method.name,
                });
            }
            if existing
                .notification
                .as_ref()
                .is_some_and(|notification| notification.name == method.name)
            {
                return Err(ExtensionRegistryError::OwnershipCollision {
                    field: "method/notification",
                    value: method.name,
                });
            }
        }
        self.additional_methods
            .entry(id.clone())
            .or_default()
            .insert(method.name.clone(), method);
        Ok(())
    }

    /// Freezes this registry and returns its canonical domain-separated digest receipt.
    pub fn freeze(&mut self) -> Result<ExtensionRegistryReceipt, ExtensionRegistryError> {
        if let Some(receipt) = &self.receipt {
            return Ok(receipt.clone());
        }
        let canonical = self.canonical_subject()?;
        let digest = sha256_bounded(canonical.as_bytes(), MAX_EXTENSION_REGISTRY_CANONICAL_BYTES)
            .map_err(|_| ExtensionRegistryError::DigestTooLarge)?
            .into_bytes();
        let receipt = ExtensionRegistryReceipt {
            digest,
            descriptor_count: self.descriptors.len(),
        };
        self.receipt = Some(receipt.clone());
        Ok(receipt)
    }

    /// Returns the frozen receipt, if this registry has been frozen.
    #[must_use]
    pub fn receipt(&self) -> Option<&ExtensionRegistryReceipt> {
        self.receipt.as_ref()
    }

    /// Returns a descriptor by its exact registered identifier.
    #[must_use]
    pub fn descriptor(&self, id: &ExtensionId) -> Option<&ExtensionDescriptor> {
        self.descriptors.get(id)
    }

    fn method(&self, id: &ExtensionId, name: &str) -> Option<&ExtensionMethodDescriptor> {
        self.descriptors
            .get(id)
            .and_then(|descriptor| {
                descriptor
                    .method
                    .as_ref()
                    .filter(|method| method.name == name)
            })
            .or_else(|| self.additional_methods.get(id)?.get(name))
    }

    /// Returns the frozen descriptors in deterministic identifier order.
    #[must_use]
    pub fn descriptors(&self) -> impl ExactSizeIterator<Item = &ExtensionDescriptor> {
        self.descriptors.values()
    }

    /// Preserves unknown peer settings as inert diagnostic data.
    #[must_use]
    pub fn preserve_unknown_peer_extensions(
        &self,
        peer: BTreeMap<ExtensionId, ExtensionSettings>,
    ) -> BTreeMap<ExtensionId, ExtensionSettings> {
        peer.into_iter()
            .filter(|(id, _)| !self.descriptors.contains_key(id))
            .collect()
    }

    /// Derives one frozen, bilateral extension set for the current exchange.
    ///
    /// The typed resolver is called only for descriptors enabled by both
    /// local gates and advertised by both peers on this exchange. The generic
    /// registry preserves the peer objects independently; it never treats
    /// JSON-object equality as compatibility.
    pub fn negotiate<R>(
        &self,
        protocol_era: ProtocolEra,
        local: &ExtensionLocalEnablement,
        client: &ClientExtensionDiscovery,
        server: &ServerExtensionDiscovery,
        resolver: &mut R,
    ) -> Result<NegotiatedExtensionSet, ExtensionNegotiationError>
    where
        R: ExtensionSettingsCompatibilityResolver,
    {
        if matches!(protocol_era, ProtocolEra::Legacy2024) {
            return Err(ExtensionNegotiationError::LegacyProtocolExcluded);
        }
        let Some(receipt) = self.receipt.clone() else {
            return Err(ExtensionNegotiationError::RegistryNotFrozen);
        };
        validate_discovery(&client.extensions, ExtensionPeer::Client)?;
        validate_discovery(&server.extensions, ExtensionPeer::Server)?;
        for id in local.configured_ids() {
            if !self.descriptors.contains_key(id) {
                return Err(ExtensionNegotiationError::UnregisteredLocalEnablement(
                    id.to_string(),
                ));
            }
        }

        let unknown_client = self.preserve_unknown_peer_extensions(client.extensions.clone());
        let unknown_server = self.preserve_unknown_peer_extensions(server.extensions.clone());
        let mut active = BTreeMap::new();
        let mut inactive = BTreeMap::new();

        for descriptor in self.descriptors.values() {
            let id = &descriptor.id;
            if !local.is_enabled(id) {
                inactive.insert(id.clone(), ExtensionInactiveReason::LocallyDisabled);
                continue;
            }

            match (client.extensions.get(id), server.extensions.get(id)) {
                (Some(client), Some(server)) => {
                    enforce_official_tasks_empty_settings(id, client)?;
                    enforce_official_tasks_empty_settings(id, server)?;
                    let effective = resolver.resolve(descriptor, client, server)?;
                    enforce_official_tasks_empty_settings(id, &effective)?;
                    let fingerprint = effective_settings_fingerprint(descriptor, &effective)?;
                    active.insert(
                        id.clone(),
                        NegotiatedExtension {
                            id: id.clone(),
                            effective_settings: EffectiveExtensionSettings {
                                settings: effective,
                                fingerprint,
                            },
                        },
                    );
                }
                (None, None) => {
                    inactive.insert(id.clone(), ExtensionInactiveReason::NotAdvertised);
                }
                (None, Some(_)) => match descriptor.resolver.fallback {
                    ExtensionFallbackPolicy::ServerInactiveFallback => {
                        inactive
                            .insert(id.clone(), ExtensionInactiveReason::ServerInactiveFallback);
                    }
                    ExtensionFallbackPolicy::RejectOneSided
                    | ExtensionFallbackPolicy::ClientInactiveFallback => {
                        return Err(ExtensionNegotiationError::OneSidedSupport {
                            id: id.to_string(),
                            missing: ExtensionPeer::Client,
                        });
                    }
                },
                (Some(_), None) => match descriptor.resolver.fallback {
                    ExtensionFallbackPolicy::ClientInactiveFallback => {
                        inactive
                            .insert(id.clone(), ExtensionInactiveReason::ClientInactiveFallback);
                    }
                    ExtensionFallbackPolicy::RejectOneSided
                    | ExtensionFallbackPolicy::ServerInactiveFallback => {
                        return Err(ExtensionNegotiationError::OneSidedSupport {
                            id: id.to_string(),
                            missing: ExtensionPeer::Server,
                        });
                    }
                },
            }
        }

        Ok(NegotiatedExtensionSet {
            registry_receipt: receipt,
            protocol_era,
            active,
            inactive,
            unknown_client,
            unknown_server,
        })
    }

    fn canonical_subject(&self) -> Result<String, ExtensionRegistryError> {
        let rows = self
            .descriptors
            .values()
            .map(|descriptor| {
                canonical_descriptor_row(descriptor, self.additional_methods.get(&descriptor.id))
            })
            .collect::<Vec<_>>();
        let json = serde_json::to_string(&("fastmcp.ext-01.descriptor-registry.v1", rows))
            .map_err(|_| ExtensionRegistryError::DigestTooLarge)?;
        // EXT-01 freezes the canonical subject as escaped JSON token bytes,
        // rather than as an ordinary JSON document. Keep that framing before
        // hashing so the public receipt matches the frozen digest contract.
        let subject = json.replace('"', r#"\""#);
        if subject.len() > MAX_EXTENSION_REGISTRY_CANONICAL_BYTES {
            return Err(ExtensionRegistryError::DigestTooLarge);
        }
        Ok(subject)
    }
}

fn enforce_official_tasks_empty_settings(
    id: &ExtensionId,
    settings: &ExtensionSettings,
) -> Result<(), ExtensionNegotiationError> {
    if id.as_str() != OFFICIAL_TASKS_EXTENSION_ID || settings.as_object().is_empty() {
        return Ok(());
    }
    Err(ExtensionNegotiationError::SettingsCompatibilityRejected(
        id.to_string(),
    ))
}

fn validate_discovery(
    extensions: &BTreeMap<ExtensionId, ExtensionSettings>,
    peer: ExtensionPeer,
) -> Result<(), ExtensionNegotiationError> {
    if extensions.len() > MAX_EXTENSION_DESCRIPTORS {
        return Err(ExtensionNegotiationError::DiscoveryTooManyExtensions(peer));
    }
    Ok(())
}

fn effective_settings_fingerprint(
    descriptor: &ExtensionDescriptor,
    effective: &ExtensionSettings,
) -> Result<[u8; 32], ExtensionNegotiationError> {
    let subject = serde_json::to_vec(&serde_json::json!({
        "domain": "fastmcp.ext-01.effective-settings.v1",
        "id": descriptor.id.as_str(),
        "resolver": [descriptor.resolver.id, descriptor.resolver.version],
        "clientSchema": descriptor.client_settings.schema_id,
        "serverSchema": descriptor.server_settings.schema_id,
        "effective": canonicalize_value(&Value::Object(effective.as_object().clone())),
    }))
    .map_err(|_| ExtensionNegotiationError::EffectiveSettingsTooLarge(descriptor.id.to_string()))?;
    if subject.len() > MAX_EXTENSION_REGISTRY_CANONICAL_BYTES {
        return Err(ExtensionNegotiationError::EffectiveSettingsTooLarge(
            descriptor.id.to_string(),
        ));
    }
    sha256_bounded(&subject, MAX_EXTENSION_REGISTRY_CANONICAL_BYTES)
        .map(|digest| digest.into_bytes())
        .map_err(|_| {
            ExtensionNegotiationError::EffectiveSettingsTooLarge(descriptor.id.to_string())
        })
}

fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_value).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize_value(value)))
                .collect(),
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.clone(),
    }
}

impl NegotiatedExtensionSet {
    /// Admits an active extension capability for one modern request.
    pub fn admit_capability<'a>(
        &self,
        registry: &'a ExtensionDescriptorRegistry,
        request_era: ProtocolEra,
        capability: &ExtensionId,
    ) -> Result<&'a ExtensionDescriptor, ExtensionDispatchError> {
        self.ensure_request_era(request_era)?;
        self.ensure_registry(registry)?;
        if !self.active.contains_key(capability) {
            return Err(ExtensionDispatchError::InactiveCapability(
                capability.to_string(),
            ));
        }
        registry
            .descriptor(capability)
            .ok_or(ExtensionDispatchError::RegistryReceiptMismatch)
    }

    /// Admits a method owned by an active capability for one modern request.
    pub fn admit_method<'a>(
        &self,
        registry: &'a ExtensionDescriptorRegistry,
        request_era: ProtocolEra,
        capability: &ExtensionId,
        name: &str,
        direction: ExtensionDirection,
    ) -> Result<&'a ExtensionDescriptor, ExtensionDispatchError> {
        validate_dispatch_name(name)?;
        let descriptor = self.admit_capability(registry, request_era, capability)?;
        let Some(method) = registry.method(capability, name) else {
            return Err(ExtensionDispatchError::CapabilityDoesNotOwn {
                capability: capability.to_string(),
                field: "method",
                value: name.to_owned(),
            });
        };
        if method.direction != direction {
            return Err(ExtensionDispatchError::DirectionMismatch {
                field: "method",
                value: name.to_owned(),
                expected: direction,
                actual: method.direction,
            });
        }
        Ok(descriptor)
    }

    /// Admits a notification owned by an active capability for one modern request.
    pub fn admit_notification<'a>(
        &self,
        registry: &'a ExtensionDescriptorRegistry,
        request_era: ProtocolEra,
        capability: &ExtensionId,
        name: &str,
        direction: ExtensionDirection,
    ) -> Result<&'a ExtensionDescriptor, ExtensionDispatchError> {
        validate_dispatch_name(name)?;
        let descriptor = self.admit_capability(registry, request_era, capability)?;
        let Some(notification) = descriptor.notification.as_ref() else {
            return Err(ExtensionDispatchError::CapabilityDoesNotOwn {
                capability: capability.to_string(),
                field: "notification",
                value: name.to_owned(),
            });
        };
        if notification.name != name {
            return Err(ExtensionDispatchError::CapabilityDoesNotOwn {
                capability: capability.to_string(),
                field: "notification",
                value: name.to_owned(),
            });
        }
        if notification.direction != direction {
            return Err(ExtensionDispatchError::DirectionMismatch {
                field: "notification",
                value: name.to_owned(),
                expected: direction,
                actual: notification.direction,
            });
        }
        Ok(descriptor)
    }

    /// Admits a result discriminator owned by an active capability for one modern request.
    pub fn admit_result_discriminator<'a>(
        &self,
        registry: &'a ExtensionDescriptorRegistry,
        request_era: ProtocolEra,
        capability: &ExtensionId,
        discriminator: &str,
    ) -> Result<&'a ExtensionDescriptor, ExtensionDispatchError> {
        validate_dispatch_name(discriminator)?;
        let descriptor = self.admit_capability(registry, request_era, capability)?;
        if descriptor.result_discriminator.as_deref() != Some(discriminator) {
            return Err(ExtensionDispatchError::CapabilityDoesNotOwn {
                capability: capability.to_string(),
                field: "result discriminator",
                value: discriminator.to_owned(),
            });
        }
        Ok(descriptor)
    }

    fn ensure_registry(
        &self,
        registry: &ExtensionDescriptorRegistry,
    ) -> Result<(), ExtensionDispatchError> {
        if registry.receipt() == Some(&self.registry_receipt) {
            Ok(())
        } else {
            Err(ExtensionDispatchError::RegistryReceiptMismatch)
        }
    }

    fn ensure_request_era(&self, request_era: ProtocolEra) -> Result<(), ExtensionDispatchError> {
        if matches!(request_era, ProtocolEra::Legacy2024) {
            return Err(ExtensionDispatchError::LegacyProtocolExcluded);
        }
        if self.protocol_era != request_era {
            return Err(ExtensionDispatchError::ProtocolEraMismatch {
                negotiated: self.protocol_era,
                request: request_era,
            });
        }
        Ok(())
    }
}

fn validate_dispatch_name(name: &str) -> Result<(), ExtensionDispatchError> {
    if name.len() > MAX_EXTENSION_MEMBER_NAME_BYTES {
        return Err(ExtensionDispatchError::NameTooLong(name.to_owned()));
    }
    Ok(())
}

fn validate_descriptor(descriptor: &ExtensionDescriptor) -> Result<(), ExtensionRegistryError> {
    for (field, value) in [
        (
            "client settings schema",
            descriptor.client_settings.schema_id.as_str(),
        ),
        (
            "client settings codec",
            descriptor.client_settings.codec_id.as_str(),
        ),
        (
            "server settings schema",
            descriptor.server_settings.schema_id.as_str(),
        ),
        (
            "server settings codec",
            descriptor.server_settings.codec_id.as_str(),
        ),
        ("resolver", descriptor.resolver.id.as_str()),
    ] {
        validate_descriptor_identity(field, value)?;
    }
    if let Some(method) = &descriptor.method {
        validate_extension_method(method)?;
    }
    if let Some(notification) = &descriptor.notification {
        validate_member_name("notification", &notification.name)?;
        if core_or_legacy_method(&notification.name) {
            return Err(ExtensionRegistryError::CoreNotificationCollision(
                notification.name.clone(),
            ));
        }
        if descriptor
            .method
            .as_ref()
            .is_some_and(|method| method.name == notification.name)
        {
            return Err(ExtensionRegistryError::LocalOwnershipCollision {
                field: "method/notification",
                value: notification.name.clone(),
            });
        }
    }
    if let Some(discriminator) = &descriptor.result_discriminator {
        validate_member_name("result discriminator", discriminator)?;
        if matches!(discriminator.as_str(), "complete" | "input_required") {
            return Err(ExtensionRegistryError::CoreResultDiscriminatorCollision(
                discriminator.clone(),
            ));
        }
    }
    if descriptor.routing_headers.len() > MAX_EXTENSION_ROUTING_HEADERS {
        return Err(ExtensionRegistryError::LocalOwnershipCollision {
            field: "routing headers",
            value: descriptor.id.to_string(),
        });
    }
    for (index, header) in descriptor.routing_headers.iter().enumerate() {
        if header.name.is_empty() {
            return Err(ExtensionRegistryError::MissingOwner("routing header"));
        }
        if header.name.len() > MAX_EXTENSION_ROUTING_HEADER_BYTES {
            return Err(ExtensionRegistryError::MemberNameTooLong {
                field: "routing header",
                value: header.name.clone(),
            });
        }
        if descriptor.routing_headers[..index]
            .iter()
            .any(|prior| prior.name.eq_ignore_ascii_case(&header.name))
        {
            return Err(ExtensionRegistryError::LocalOwnershipCollision {
                field: "routing header",
                value: header.name.clone(),
            });
        }
    }
    if let Some(correlation) = &descriptor.stdio_correlation {
        if correlation.metadata_key.is_empty() {
            return Err(ExtensionRegistryError::MissingOwner("stdio correlation"));
        }
        ExtensionId::parse(correlation.metadata_key.clone())?;
        if correlation.methods.is_empty()
            || correlation.methods.len() > MAX_STDIO_CORRELATION_METHODS
        {
            return Err(ExtensionRegistryError::MissingOwner("stdio correlation"));
        }
        let Some(notification) = &descriptor.notification else {
            return Err(ExtensionRegistryError::MissingOwner("stdio notification"));
        };
        if notification.direction != correlation.direction
            || !correlation
                .methods
                .iter()
                .any(|method| method == &notification.name)
        {
            return Err(ExtensionRegistryError::LocalOwnershipCollision {
                field: "stdio correlation notification",
                value: correlation.metadata_key.clone(),
            });
        }
        for (index, method) in correlation.methods.iter().enumerate() {
            validate_member_name("stdio correlation method", method)?;
            if correlation.methods[..index].contains(method) {
                return Err(ExtensionRegistryError::LocalOwnershipCollision {
                    field: "stdio correlation method",
                    value: method.clone(),
                });
            }
        }
    }
    Ok(())
}

fn validate_extension_method(
    method: &ExtensionMethodDescriptor,
) -> Result<(), ExtensionRegistryError> {
    validate_member_name("method", &method.name)?;
    if core_or_legacy_method(&method.name) {
        return Err(ExtensionRegistryError::CoreMethodCollision(
            method.name.clone(),
        ));
    }
    if method.direction == ExtensionDirection::ClientToServer {
        if method.http_era_disposition.is_none() {
            return Err(ExtensionRegistryError::MissingHttpEraDisposition(
                method.name.clone(),
            ));
        }
        if method.legacy_fallback {
            return Err(ExtensionRegistryError::LegacyFallbackContradiction(
                method.name.clone(),
            ));
        }
    } else if method.http_era_disposition.is_some() {
        return Err(ExtensionRegistryError::MissingHttpEraDisposition(
            method.name.clone(),
        ));
    } else if method.legacy_fallback {
        return Err(ExtensionRegistryError::LegacyFallbackContradiction(
            method.name.clone(),
        ));
    }
    Ok(())
}

fn validate_descriptor_identity(
    field: &'static str,
    value: &str,
) -> Result<(), ExtensionRegistryError> {
    if value.is_empty() {
        return Err(ExtensionRegistryError::MissingOwner(field));
    }
    if value.len() > MAX_EXTENSION_MEMBER_NAME_BYTES {
        return Err(ExtensionRegistryError::MemberNameTooLong {
            field,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn validate_member_name(field: &'static str, value: &str) -> Result<(), ExtensionRegistryError> {
    if value.is_empty() {
        return Err(ExtensionRegistryError::MissingOwner(field));
    }
    if value.len() > MAX_EXTENSION_MEMBER_NAME_BYTES {
        return Err(ExtensionRegistryError::MemberNameTooLong {
            field,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn ensure_no_cross_owner_collision(
    left: &ExtensionDescriptor,
    right: &ExtensionDescriptor,
) -> Result<(), ExtensionRegistryError> {
    let collision = |field: &'static str, left: Option<&str>, right: Option<&str>| {
        (left.zip(right).filter(|(a, b)| a == b)).map(|(value, _)| {
            ExtensionRegistryError::OwnershipCollision {
                field,
                value: value.to_owned(),
            }
        })
    };
    if let Some(error) = collision(
        "method",
        left.method.as_ref().map(|m| m.name.as_str()),
        right.method.as_ref().map(|m| m.name.as_str()),
    ) {
        return Err(error);
    }
    if let Some(error) = collision(
        "notification",
        left.notification.as_ref().map(|n| n.name.as_str()),
        right.notification.as_ref().map(|n| n.name.as_str()),
    ) {
        return Err(error);
    }
    if let Some(error) = collision(
        "method/notification",
        left.method.as_ref().map(|m| m.name.as_str()),
        right.notification.as_ref().map(|n| n.name.as_str()),
    ) {
        return Err(error);
    }
    if let Some(error) = collision(
        "method/notification",
        left.notification.as_ref().map(|n| n.name.as_str()),
        right.method.as_ref().map(|m| m.name.as_str()),
    ) {
        return Err(error);
    }
    if let Some(error) = collision(
        "result discriminator",
        left.result_discriminator.as_deref(),
        right.result_discriminator.as_deref(),
    ) {
        return Err(error);
    }
    for lhs in &left.routing_headers {
        for rhs in &right.routing_headers {
            if lhs.name.eq_ignore_ascii_case(&rhs.name) {
                return Err(ExtensionRegistryError::OwnershipCollision {
                    field: "routing header",
                    value: lhs.name.clone(),
                });
            }
        }
    }
    if let (Some(lhs), Some(rhs)) = (&left.stdio_correlation, &right.stdio_correlation) {
        if lhs.metadata_key == rhs.metadata_key {
            return Err(ExtensionRegistryError::OwnershipCollision {
                field: "metadata key",
                value: lhs.metadata_key.clone(),
            });
        }
        for method in &lhs.methods {
            if rhs.methods.contains(method) && lhs.direction == rhs.direction {
                return Err(ExtensionRegistryError::OwnershipCollision {
                    field: "stdio correlation method",
                    value: method.clone(),
                });
            }
        }
    }
    Ok(())
}

fn core_or_legacy_method(method: &str) -> bool {
    final_2026_07_28_method(method).is_some() || legacy_2024_11_05_method(method).is_some()
}

fn canonical_descriptor_row(
    descriptor: &ExtensionDescriptor,
    additional_methods: Option<&BTreeMap<String, ExtensionMethodDescriptor>>,
) -> Value {
    if additional_methods.is_none_or(|methods| methods.is_empty()) {
        return serde_json::json!({
            "id": descriptor.id.as_str(),
            "clientSchema": descriptor.client_settings.schema_id,
            "clientCodec": descriptor.client_settings.codec_id,
            "serverSchema": descriptor.server_settings.schema_id,
            "serverCodec": descriptor.server_settings.codec_id,
            "resolver": [descriptor.resolver.id, descriptor.resolver.version, format!("{:?}", descriptor.resolver.fallback)],
            "method": descriptor.method.as_ref().map(|m| (&m.name, format!("{:?}", m.direction), m.http_era_disposition.map(|e| format!("{:?}", e)), m.legacy_fallback)),
            "notification": descriptor.notification.as_ref().map(|n| (&n.name, format!("{:?}", n.direction))),
            "resultDiscriminator": descriptor.result_discriminator,
            "routingHeaders": descriptor.routing_headers.iter().map(|h| &h.name).collect::<Vec<_>>(),
            "stdio": descriptor.stdio_correlation.as_ref().map(|s| (&s.metadata_key, &s.methods, format!("{:?}", s.direction))),
        });
    }
    let mut methods = descriptor
        .method
        .iter()
        .chain(
            additional_methods
                .into_iter()
                .flat_map(|methods| methods.values()),
        )
        .map(|method| {
            (
                method.name.clone(),
                format!("{:?}", method.direction),
                method
                    .http_era_disposition
                    .map(|disposition| format!("{disposition:?}")),
                method.legacy_fallback,
            )
        })
        .collect::<Vec<_>>();
    methods.sort_by(|left, right| left.0.cmp(&right.0));
    serde_json::json!({
        "id": descriptor.id.as_str(),
        "clientSchema": descriptor.client_settings.schema_id,
        "clientCodec": descriptor.client_settings.codec_id,
        "serverSchema": descriptor.server_settings.schema_id,
        "serverCodec": descriptor.server_settings.codec_id,
        "resolver": [descriptor.resolver.id, descriptor.resolver.version, format!("{:?}", descriptor.resolver.fallback)],
        "methods": methods,
        "notification": descriptor.notification.as_ref().map(|n| (&n.name, format!("{:?}", n.direction))),
        "resultDiscriminator": descriptor.result_discriminator,
        "routingHeaders": descriptor.routing_headers.iter().map(|h| &h.name).collect::<Vec<_>>(),
        "stdio": descriptor.stdio_correlation.as_ref().map(|s| (&s.metadata_key, &s.methods, format!("{:?}", s.direction))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn descriptor(
        id: ExtensionId,
        method: &str,
        notification: &str,
        result_discriminator: &str,
    ) -> ExtensionDescriptor {
        ExtensionDescriptor {
            id,
            client_settings: ExtensionSettingsSchema {
                schema_id: "client-weather-v1".to_owned(),
                codec_id: "client-weather-codec-v1".to_owned(),
            },
            server_settings: ExtensionSettingsSchema {
                schema_id: "server-weather-v1".to_owned(),
                codec_id: "server-weather-codec-v1".to_owned(),
            },
            resolver: ExtensionNegotiationResolver {
                id: "weather-compatibility-v1".to_owned(),
                version: 1,
                fallback: ExtensionFallbackPolicy::RejectOneSided,
            },
            method: Some(ExtensionMethodDescriptor {
                name: method.to_owned(),
                direction: ExtensionDirection::ClientToServer,
                http_era_disposition: Some(ExtensionHttpEraDisposition::ModernExclusive),
                legacy_fallback: false,
            }),
            notification: Some(ExtensionNotificationDescriptor {
                name: notification.to_owned(),
                direction: ExtensionDirection::ServerToClient,
            }),
            result_discriminator: Some(result_discriminator.to_owned()),
            routing_headers: vec![ExtensionRoutingHeaderDescriptor {
                name: "Mcp-Weather".to_owned(),
            }],
            stdio_correlation: None,
        }
    }

    #[test]
    fn ext_03_final_extension_identifier_wire_grammar_one_variable_negative() {
        let official = official_tasks_extension_id();
        assert_eq!(official.as_str(), OFFICIAL_TASKS_EXTENSION_ID);
        assert!(ExtensionId::parse("Example/tasks").is_ok());

        assert_eq!(
            ExtensionId::parse(format!("{OFFICIAL_TASKS_EXTENSION_ID}_")),
            Err(ExtensionRegistryError::InvalidIdentifier(
                "io.modelcontextprotocol/tasks_".to_owned()
            )),
            "only the terminal non-alphanumeric name byte changes from the admitted official key"
        );
    }

    #[test]
    fn task_01_official_tasks_public_registry_positive() {
        let mut registry = ExtensionDescriptorRegistry::new();
        let id = register_official_tasks_extension(&mut registry)
            .expect("the public official Tasks surface registers atomically");
        let descriptor = registry
            .descriptor(&id)
            .expect("the public Tasks registration retains its descriptor");
        assert_eq!(descriptor.id.as_str(), OFFICIAL_TASKS_EXTENSION_ID);
        assert_eq!(
            descriptor.client_settings.schema_id,
            OFFICIAL_TASKS_EMPTY_SETTINGS_SCHEMA_ID
        );
        assert_eq!(
            descriptor.server_settings.schema_id,
            OFFICIAL_TASKS_EMPTY_SETTINGS_SCHEMA_ID
        );
        assert_eq!(
            descriptor
                .method
                .as_ref()
                .map(|method| method.name.as_str()),
            Some(OFFICIAL_TASKS_METHODS[0])
        );
        assert_eq!(
            descriptor.result_discriminator.as_deref(),
            Some(OFFICIAL_TASKS_RESULT_DISCRIMINATOR)
        );
        registry.freeze().expect("Tasks registry freezes");

        let client = ClientExtensionDiscovery {
            extensions: BTreeMap::from([(id.clone(), official_tasks_empty_settings())]),
        };
        let server = ServerExtensionDiscovery {
            extensions: BTreeMap::from([(id.clone(), official_tasks_empty_settings())]),
        };
        let mut local = ExtensionLocalEnablement::default();
        local.enable(id.clone());
        let mut resolver =
            |_descriptor: &ExtensionDescriptor,
             _client: &ExtensionSettings,
             _server: &ExtensionSettings| { Ok(official_tasks_empty_settings()) };

        let negotiated = registry
            .negotiate(
                ProtocolEra::Modern2026,
                &local,
                &client,
                &server,
                &mut resolver,
            )
            .expect("current client and server capabilities negotiate Tasks");
        for method in OFFICIAL_TASKS_METHODS {
            assert_eq!(
                negotiated
                    .admit_method(
                        &registry,
                        ProtocolEra::Modern2026,
                        &id,
                        method,
                        ExtensionDirection::ClientToServer,
                    )
                    .expect("registered Tasks request is admitted")
                    .id,
                id
            );
        }
        for method in ["tasks/list", "tasks/submit"] {
            assert_eq!(
                negotiated.admit_method(
                    &registry,
                    ProtocolEra::Modern2026,
                    &id,
                    method,
                    ExtensionDirection::ClientToServer,
                ),
                Err(ExtensionDispatchError::CapabilityDoesNotOwn {
                    capability: id.to_string(),
                    field: "method",
                    value: method.to_owned(),
                }),
                "the official Tasks registration owns no additional request methods"
            );
        }
        assert_eq!(
            negotiated
                .admit_notification(
                    &registry,
                    ProtocolEra::Modern2026,
                    &id,
                    OFFICIAL_TASKS_NOTIFICATION,
                    ExtensionDirection::ServerToClient,
                )
                .expect("registered Tasks notification is admitted")
                .id,
            id
        );
        assert_eq!(
            negotiated
                .admit_result_discriminator(
                    &registry,
                    ProtocolEra::Modern2026,
                    &id,
                    OFFICIAL_TASKS_RESULT_DISCRIMINATOR,
                )
                .expect("official Tasks tools/call result discriminator is admitted")
                .id,
            id
        );
    }

    #[test]
    fn task_01_official_tasks_undeclared_result_discriminator_one_variable_negative() {
        let mut registry = ExtensionDescriptorRegistry::new();
        let id = register_official_tasks_extension(&mut registry)
            .expect("the public official Tasks surface registers");
        registry.freeze().expect("Tasks registry freezes");
        let client = ClientExtensionDiscovery {
            extensions: BTreeMap::from([(id.clone(), official_tasks_empty_settings())]),
        };
        let server = ServerExtensionDiscovery {
            extensions: BTreeMap::from([(id.clone(), official_tasks_empty_settings())]),
        };
        let mut local = ExtensionLocalEnablement::default();
        local.enable(id.clone());
        let mut resolver =
            |_descriptor: &ExtensionDescriptor,
             _client: &ExtensionSettings,
             _server: &ExtensionSettings| { Ok(official_tasks_empty_settings()) };
        let negotiated = registry
            .negotiate(
                ProtocolEra::Modern2026,
                &local,
                &client,
                &server,
                &mut resolver,
            )
            .expect("current client and server capabilities negotiate Tasks");

        let wrong_discriminator = "task-other";
        assert_eq!(
            negotiated.admit_result_discriminator(
                &registry,
                ProtocolEra::Modern2026,
                &id,
                wrong_discriminator,
            ),
            Err(ExtensionDispatchError::CapabilityDoesNotOwn {
                capability: id.to_string(),
                field: "result discriminator",
                value: wrong_discriminator.to_owned(),
            }),
            "only the undeclared result discriminator differs from the admitted task value"
        );
    }

    #[test]
    fn task_01_official_tasks_nonempty_client_settings_one_variable_negative() {
        let mut registry = ExtensionDescriptorRegistry::new();
        let id = register_official_tasks_extension(&mut registry)
            .expect("the public official Tasks surface registers");
        let receipt = registry.freeze().expect("Tasks registry freezes");
        let client = ClientExtensionDiscovery {
            extensions: BTreeMap::from([(id.clone(), official_tasks_empty_settings())]),
        };
        let server = ServerExtensionDiscovery {
            extensions: BTreeMap::from([(id.clone(), official_tasks_empty_settings())]),
        };
        let mut local = ExtensionLocalEnablement::default();
        local.enable(id.clone());
        let resolver_calls = std::cell::Cell::new(0);
        let mut resolver = |_descriptor: &ExtensionDescriptor,
                            _client: &ExtensionSettings,
                            _server: &ExtensionSettings| {
            resolver_calls.set(resolver_calls.get() + 1);
            Ok(official_tasks_empty_settings())
        };

        registry
            .negotiate(
                ProtocolEra::Modern2026,
                &local,
                &client,
                &server,
                &mut resolver,
            )
            .expect("the empty-settings baseline negotiates Tasks");
        assert_eq!(resolver_calls.get(), 1);

        let mut planted_client = client.clone();
        planted_client.extensions.insert(
            id.clone(),
            ExtensionSettings::new(json!({"unexpected": true}))
                .expect("the one-field mutation is generic extension JSON"),
        );

        assert_eq!(
            registry.negotiate(
                ProtocolEra::Modern2026,
                &local,
                &planted_client,
                &server,
                &mut resolver,
            ),
            Err(ExtensionNegotiationError::SettingsCompatibilityRejected(
                id.to_string()
            )),
            "only adding one client settings field rejects the exact empty Tasks settings"
        );
        assert_eq!(
            resolver_calls.get(),
            1,
            "rejected admission cannot invoke the resolver"
        );
        assert_eq!(registry.receipt(), Some(&receipt));
    }

    #[test]
    fn ext_03_final_core_method_collision_one_variable_negative() {
        let baseline = descriptor(
            ExtensionId::parse("com.example/discover").expect("valid extension ID"),
            "com.example/discover",
            "com.example/discover_changed",
            "com.example/discover_result",
        );
        assert!(validate_descriptor(&baseline).is_ok());

        let mut planted = baseline.clone();
        planted
            .method
            .as_mut()
            .expect("baseline owns an extension method")
            .name = crate::methods::SERVER_DISCOVER.to_owned();
        assert_eq!(
            validate_descriptor(&planted),
            Err(ExtensionRegistryError::CoreMethodCollision(
                crate::methods::SERVER_DISCOVER.to_owned()
            )),
            "only replacing the extension method with final server/discover makes it invalid"
        );
    }

    #[test]
    fn ext_01_unit_bilateral_negotiation_and_directional_dispatch_positive() {
        let id = ExtensionId::parse("com.example/weather").expect("valid extension ID");
        let mut registry = ExtensionDescriptorRegistry::new();
        registry
            .register(descriptor(
                id.clone(),
                "com.example/weather",
                "com.example/weather_changed",
                "com.example/weather_result",
            ))
            .expect("descriptor registers");
        registry
            .freeze()
            .expect("registry freezes before negotiation");

        let client_settings = ExtensionSettings::new(json!({
            "unit": "celsius",
            "preserved": [null, 1.5, {"nested": true}],
        }))
        .expect("current-message client settings are bounded JSON");
        let server_settings = ExtensionSettings::new(json!({"maxCities": 4}))
            .expect("server discovery settings are bounded JSON");
        let unknown_id = ExtensionId::parse("org.example/diagnostic")
            .expect("unknown but structurally valid ID");

        let client = ClientExtensionDiscovery {
            extensions: BTreeMap::from([
                (id.clone(), client_settings),
                (
                    unknown_id.clone(),
                    ExtensionSettings::new(json!({"opaque": null}))
                        .expect("bounded unknown settings"),
                ),
            ]),
        };
        let server = ServerExtensionDiscovery {
            extensions: BTreeMap::from([(id.clone(), server_settings)]),
        };
        let mut local = ExtensionLocalEnablement::default();
        local.enable(id.clone());
        let mut resolver = |descriptor: &ExtensionDescriptor,
                            client: &ExtensionSettings,
                            server: &ExtensionSettings| {
            assert_eq!(descriptor.resolver.id, "weather-compatibility-v1");
            ExtensionSettings::new(json!({
                "unit": client.as_object()["unit"].clone(),
                "maxCities": server.as_object()["maxCities"].clone(),
            }))
            .map_err(|_| {
                ExtensionNegotiationError::SettingsCompatibilityRejected(descriptor.id.to_string())
            })
        };
        let negotiated = registry
            .negotiate(
                ProtocolEra::Modern2026,
                &local,
                &client,
                &server,
                &mut resolver,
            )
            .expect("bilateral current-message settings negotiate");

        assert_eq!(negotiated.protocol_era(), ProtocolEra::Modern2026);
        assert_eq!(negotiated.active_extensions().len(), 1);
        assert_eq!(
            negotiated
                .active(&id)
                .expect("registered bilateral extension is active")
                .effective_settings()
                .settings()
                .as_object()["unit"],
            json!("celsius")
        );
        assert_eq!(
            negotiated.unknown_client_extensions()[&unknown_id].as_object()["opaque"],
            Value::Null,
            "unknown peer data remains diagnostic and cannot activate dispatch"
        );
        assert_eq!(
            negotiated
                .admit_capability(&registry, ProtocolEra::Modern2026, &id)
                .expect("developer-opted-in bilateral capability is active")
                .id,
            id
        );
        assert_eq!(
            negotiated
                .admit_method(
                    &registry,
                    ProtocolEra::Modern2026,
                    &id,
                    "com.example/weather",
                    ExtensionDirection::ClientToServer,
                )
                .expect("active method dispatch")
                .id,
            id
        );
        assert_eq!(
            negotiated
                .admit_notification(
                    &registry,
                    ProtocolEra::Modern2026,
                    &id,
                    "com.example/weather_changed",
                    ExtensionDirection::ServerToClient,
                )
                .expect("active notification dispatch")
                .id,
            id
        );
        assert_eq!(
            negotiated
                .admit_result_discriminator(
                    &registry,
                    ProtocolEra::Modern2026,
                    &id,
                    "com.example/weather_result",
                )
                .expect("active result discriminator dispatch")
                .id,
            id
        );
        assert_eq!(
            negotiated.admit_notification(
                &registry,
                ProtocolEra::Modern2026,
                &id,
                "com.example/weather_changed",
                ExtensionDirection::ClientToServer,
            ),
            Err(ExtensionDispatchError::DirectionMismatch {
                field: "notification",
                value: "com.example/weather_changed".to_owned(),
                expected: ExtensionDirection::ClientToServer,
                actual: ExtensionDirection::ServerToClient,
            }),
            "only the requested direction changes; the same active descriptor must not dispatch"
        );
    }

    fn negotiated_weather_extension() -> (
        ExtensionDescriptorRegistry,
        ExtensionId,
        NegotiatedExtensionSet,
    ) {
        let id = ExtensionId::parse("com.example/weather").expect("valid extension ID");
        let mut registry = ExtensionDescriptorRegistry::new();
        registry
            .register(descriptor(
                id.clone(),
                "com.example/weather",
                "com.example/weather_changed",
                "com.example/weather_result",
            ))
            .expect("descriptor registers");
        registry
            .freeze()
            .expect("registry freezes before negotiation");

        let client = ClientExtensionDiscovery {
            extensions: BTreeMap::from([(
                id.clone(),
                ExtensionSettings::new(json!({"unit": "celsius"}))
                    .expect("bounded client settings"),
            )]),
        };
        let server = ServerExtensionDiscovery {
            extensions: BTreeMap::from([(
                id.clone(),
                ExtensionSettings::new(json!({"maxCities": 4})).expect("bounded server settings"),
            )]),
        };
        let mut local = ExtensionLocalEnablement::default();
        local.enable(id.clone());
        let mut resolver = |descriptor: &ExtensionDescriptor,
                            client: &ExtensionSettings,
                            server: &ExtensionSettings| {
            ExtensionSettings::new(json!({
                "unit": client.as_object()["unit"].clone(),
                "maxCities": server.as_object()["maxCities"].clone(),
            }))
            .map_err(|_| {
                ExtensionNegotiationError::SettingsCompatibilityRejected(descriptor.id.to_string())
            })
        };
        let negotiated = registry
            .negotiate(
                ProtocolEra::Modern2026,
                &local,
                &client,
                &server,
                &mut resolver,
            )
            .expect("developer opt-in and both peer settings negotiate");

        (registry, id, negotiated)
    }

    #[test]
    fn ext_02_executable_request_admission_positive() {
        let (registry, id, negotiated) = negotiated_weather_extension();

        assert_eq!(negotiated.protocol_era(), ProtocolEra::Modern2026);
        assert_eq!(negotiated.active_extensions().len(), 1);
        assert_eq!(
            negotiated
                .admit_capability(&registry, ProtocolEra::Modern2026, &id)
                .expect("active extension capability is admitted per request")
                .id,
            id
        );
        assert_eq!(
            negotiated
                .admit_method(
                    &registry,
                    ProtocolEra::Modern2026,
                    &id,
                    "com.example/weather",
                    ExtensionDirection::ClientToServer,
                )
                .expect("active extension method is admitted per request")
                .id,
            id
        );
        assert_eq!(
            negotiated
                .admit_result_discriminator(
                    &registry,
                    ProtocolEra::Modern2026,
                    &id,
                    "com.example/weather_result",
                )
                .expect("active extension result discriminator is admitted per request")
                .id,
            id
        );
    }

    #[test]
    fn ext_02_executable_request_admission_one_variable_negatives() {
        let (registry, id, negotiated) = negotiated_weather_extension();
        let active_count = negotiated.active_extensions().len();

        assert_eq!(
            negotiated.admit_capability(&registry, ProtocolEra::Legacy2024, &id),
            Err(ExtensionDispatchError::LegacyProtocolExcluded),
            "changing only the request era must exclude exact legacy admission"
        );
        assert_eq!(
            negotiated.admit_method(
                &registry,
                ProtocolEra::Modern2026,
                &id,
                "com.example/weather-other",
                ExtensionDirection::ClientToServer,
            ),
            Err(ExtensionDispatchError::CapabilityDoesNotOwn {
                capability: id.to_string(),
                field: "method",
                value: "com.example/weather-other".to_owned(),
            }),
            "changing only the method spelling must reject dispatch"
        );
        assert_eq!(
            negotiated.admit_result_discriminator(
                &registry,
                ProtocolEra::Modern2026,
                &id,
                "com.example/weather_result-other",
            ),
            Err(ExtensionDispatchError::CapabilityDoesNotOwn {
                capability: id.to_string(),
                field: "result discriminator",
                value: "com.example/weather_result-other".to_owned(),
            }),
            "changing only the result discriminator must reject dispatch"
        );
        assert_eq!(
            negotiated.active_extensions().len(),
            active_count,
            "rejected requests cannot mutate the bounded negotiated state"
        );
    }

    #[test]
    fn ext_02_developer_opt_in_and_legacy_negotiation_fail_closed() {
        let id = ExtensionId::parse("com.example/weather").expect("valid extension ID");
        let mut registry = ExtensionDescriptorRegistry::new();
        registry
            .register(descriptor(
                id.clone(),
                "com.example/weather",
                "com.example/weather_changed",
                "com.example/weather_result",
            ))
            .expect("descriptor registers");
        let receipt = registry
            .freeze()
            .expect("registry freezes before negotiation");
        let client = ClientExtensionDiscovery {
            extensions: BTreeMap::from([(
                id.clone(),
                ExtensionSettings::new(json!({})).expect("bounded client settings"),
            )]),
        };
        let server = ServerExtensionDiscovery {
            extensions: BTreeMap::from([(
                id.clone(),
                ExtensionSettings::new(json!({})).expect("bounded server settings"),
            )]),
        };
        let local = ExtensionLocalEnablement::default();
        let resolver_calls = std::cell::Cell::new(0);
        let mut resolver = |_descriptor: &ExtensionDescriptor,
                            _client: &ExtensionSettings,
                            _server: &ExtensionSettings| {
            resolver_calls.set(resolver_calls.get() + 1);
            Ok(ExtensionSettings::new(json!({})).expect("bounded effective settings"))
        };

        let unopted = registry
            .negotiate(
                ProtocolEra::Modern2026,
                &local,
                &client,
                &server,
                &mut resolver,
            )
            .expect("registered descriptors remain inactive without developer opt-in");
        assert_eq!(resolver_calls.get(), 0);
        assert_eq!(
            unopted.inactive_reason(&id),
            Some(ExtensionInactiveReason::LocallyDisabled)
        );
        assert_eq!(
            unopted.admit_capability(&registry, ProtocolEra::Modern2026, &id),
            Err(ExtensionDispatchError::InactiveCapability(id.to_string()))
        );

        assert_eq!(
            registry.negotiate(
                ProtocolEra::Legacy2024,
                &local,
                &client,
                &server,
                &mut resolver,
            ),
            Err(ExtensionNegotiationError::LegacyProtocolExcluded),
            "changing only the negotiation era must reject exact legacy before resolver execution"
        );
        assert_eq!(resolver_calls.get(), 0);
        assert_eq!(registry.receipt(), Some(&receipt));
    }

    #[test]
    fn ext_02_oversized_discovery_is_rejected_before_bounded_state_allocation() {
        let mut registry = ExtensionDescriptorRegistry::new();
        registry.freeze().expect("empty registry freezes");
        let settings = ExtensionSettings::new(json!({})).expect("bounded settings");
        let client = ClientExtensionDiscovery {
            extensions: (0..=MAX_EXTENSION_DESCRIPTORS)
                .map(|index| {
                    (
                        ExtensionId::parse(format!("com.example/diagnostic-{index}"))
                            .expect("bounded synthetic identifier"),
                        settings.clone(),
                    )
                })
                .collect(),
        };
        let mut resolver_called = false;
        let mut resolver = |_descriptor: &ExtensionDescriptor,
                            _client: &ExtensionSettings,
                            _server: &ExtensionSettings| {
            resolver_called = true;
            Ok(ExtensionSettings::new(json!({})).expect("bounded effective settings"))
        };

        assert_eq!(
            registry.negotiate(
                ProtocolEra::Modern2026,
                &ExtensionLocalEnablement::default(),
                &client,
                &ServerExtensionDiscovery::default(),
                &mut resolver,
            ),
            Err(ExtensionNegotiationError::DiscoveryTooManyExtensions(
                ExtensionPeer::Client
            ))
        );
        assert!(!resolver_called);
    }

    #[test]
    fn ext_01_unit_one_variable_collision_negative() {
        let first_id = ExtensionId::parse("com.example/first").expect("first ID");
        let second_id = ExtensionId::parse("com.example/second").expect("second ID");
        let first = descriptor(
            first_id,
            "com.example/first",
            "com.example/first_changed",
            "com.example/first_result",
        );
        let candidate = descriptor(
            second_id,
            "com.example/second",
            "com.example/second_changed",
            "com.example/second_result",
        );
        let mut registry = ExtensionDescriptorRegistry::new();
        registry.register(first).expect("baseline owner registers");
        let baseline_count = registry.descriptors().len();

        let mut planted = candidate.clone();
        planted.result_discriminator = Some("com.example/first_result".to_owned());
        assert_eq!(
            registry.register(planted),
            Err(ExtensionRegistryError::OwnershipCollision {
                field: "result discriminator",
                value: "com.example/first_result".to_owned(),
            }),
            "the otherwise valid candidate differs in only the colliding discriminator"
        );
        assert_eq!(
            registry.descriptors().len(),
            baseline_count,
            "rejected registration cannot mutate the frozen dispatch owner set"
        );
        registry
            .register(candidate)
            .expect("the unmodified one-variable baseline remains registrable");
    }

    #[test]
    fn ext_01_unit_one_level_over_settings_bound_is_rejected() {
        let mut accepted_value = Value::Null;
        for _ in 0..MAX_EXTENSION_SETTINGS_NESTING {
            accepted_value = Value::Array(vec![accepted_value]);
        }
        let accepted = ExtensionSettings::new(json!({"nested": accepted_value.clone()}))
            .expect("the exact nesting bound is admitted");

        let planted = Value::Array(vec![accepted_value.clone()]);
        assert_eq!(
            ExtensionSettings::new(json!({"nested": planted})),
            Err(ExtensionRegistryError::SettingsTooDeep),
            "only one additional nesting level changes the accepted settings object"
        );
        assert_eq!(
            accepted.as_object()["nested"],
            json!(accepted_value),
            "rejected settings cannot mutate the previously admitted object"
        );
    }
}
