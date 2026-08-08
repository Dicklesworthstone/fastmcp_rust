//! Frozen, runtime-neutral extension descriptor registry.
//!
//! This module admits extension metadata and settings only.  It deliberately
//! owns no handler, transport, authorization, or client/server runtime state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fastmcp_core::sha256_bounded;
use serde_json::{Map, Value};

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
        if prefix
            .split('.')
            .nth(1)
            .is_some_and(|label| matches!(label, "modelcontextprotocol" | "mcp"))
        {
            return Err(ExtensionRegistryError::ReservedNamespace(value));
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
    let labels = prefix.split('.').collect::<Vec<_>>();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_lowercase()
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_name(name: &str) -> bool {
    name.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
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

fn validate_settings_map(map: &Map<String, Value>) -> Result<(), ExtensionRegistryError> {
    if map.len() > MAX_EXTENSION_SETTINGS_ENTRIES {
        return Err(ExtensionRegistryError::SettingsTooManyEntries);
    }
    for (key, value) in map {
        if key.len() > MAX_EXTENSION_SETTINGS_KEY_BYTES {
            return Err(ExtensionRegistryError::SettingsKeyTooLong);
        }
        validate_settings_value(value, 0)?;
        let encoded = serde_json::to_vec(value).map_err(|_| ExtensionRegistryError::SettingsTooLarge)?;
        if encoded.len() > MAX_EXTENSION_SETTINGS_VALUE_BYTES {
            return Err(ExtensionRegistryError::SettingsTooLarge);
        }
    }
    Ok(())
}

fn validate_settings_value(
    value: &Value,
    depth: usize,
) -> Result<(), ExtensionRegistryError> {
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
    /// Whether exact legacy fallback is declared.
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

/// Acyclic protocol-only descriptor registry.
#[derive(Clone, Debug, Default)]
pub struct ExtensionDescriptorRegistry {
    descriptors: BTreeMap<ExtensionId, ExtensionDescriptor>,
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
        self.descriptors.insert(descriptor.id.clone(), descriptor);
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

    fn canonical_subject(&self) -> Result<String, ExtensionRegistryError> {
        let rows = self
            .descriptors
            .values()
            .map(canonical_descriptor_row)
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
        if value.is_empty() {
            return Err(ExtensionRegistryError::MissingOwner(field));
        }
    }
    if let Some(method) = &descriptor.method {
        if method.name.is_empty() {
            return Err(ExtensionRegistryError::MissingOwner("method"));
        }
        if core_or_legacy_method(&method.name) {
            return Err(ExtensionRegistryError::CoreMethodCollision(
                method.name.clone(),
            ));
        }
        if method.direction == ExtensionDirection::ClientToServer {
            let Some(disposition) = method.http_era_disposition else {
                return Err(ExtensionRegistryError::MissingHttpEraDisposition(
                    method.name.clone(),
                ));
            };
            if disposition == ExtensionHttpEraDisposition::ModernExclusive && method.legacy_fallback
            {
                return Err(ExtensionRegistryError::LegacyFallbackContradiction(
                    method.name.clone(),
                ));
            }
        } else if method.http_era_disposition.is_some() {
            return Err(ExtensionRegistryError::MissingHttpEraDisposition(
                method.name.clone(),
            ));
        }
    }
    if descriptor
        .notification
        .as_ref()
        .is_some_and(|item| item.name.is_empty())
    {
        return Err(ExtensionRegistryError::MissingOwner("notification"));
    }
    if descriptor
        .result_discriminator
        .as_ref()
        .is_some_and(String::is_empty)
    {
        return Err(ExtensionRegistryError::MissingOwner("result discriminator"));
    }
    if descriptor
        .routing_headers
        .iter()
        .any(|header| header.name.is_empty())
    {
        return Err(ExtensionRegistryError::MissingOwner("routing header"));
    }
    if descriptor.stdio_correlation.as_ref().is_some_and(|item| {
        item.metadata_key.is_empty()
            || item.methods.is_empty()
            || item.methods.iter().any(String::is_empty)
    }) {
        return Err(ExtensionRegistryError::MissingOwner("stdio correlation"));
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
    matches!(
        method,
        "initialize"
            | "ping"
            | "tools/list"
            | "tools/call"
            | "resources/list"
            | "resources/templates/list"
            | "resources/read"
            | "prompts/list"
            | "prompts/get"
            | "logging/setLevel"
            | "completion/complete"
            | "sampling/createMessage"
            | "roots/list"
            | "resources/subscribe"
            | "resources/unsubscribe"
            | "notifications/initialized"
            | "notifications/cancelled"
            | "notifications/message"
            | "notifications/progress"
            | "notifications/prompts/list_changed"
            | "notifications/resources/list_changed"
            | "notifications/resources/updated"
            | "notifications/roots/list_changed"
            | "notifications/tools/list_changed"
    )
}

fn canonical_descriptor_row(descriptor: &ExtensionDescriptor) -> Value {
    serde_json::json!({
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
    })
}
