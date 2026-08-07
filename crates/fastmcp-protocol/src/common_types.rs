//! Final MCP common wire types kept separate while the legacy type surface is migrated.
//!
//! This module owns structural admission and byte-preserving serialization for the PRT-02.A
//! common-type slice.  Scheme-specific fetching, rendering, and authorization policies remain
//! outside this wire layer.

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A structural rejection at the protocol wire boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommonTypeError {
    /// A value did not have the final-schema shape.
    Invalid(&'static str),
    /// A supplied value exceeded a bounded wire limit.
    TooLong(&'static str),
}

impl fmt::Display for CommonTypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(field) => write!(formatter, "invalid {field}"),
            Self::TooLong(field) => write!(formatter, "{field} exceeds its wire limit"),
        }
    }
}

impl std::error::Error for CommonTypeError {}

/// Maximum encoded bytes admitted for ordinary URI wire fields.
pub const MAX_ABSOLUTE_URI_BYTES: usize = 64 * 1024;
/// Maximum UTF-8 bytes admitted for a peer cancellation reason.
pub const MAX_CANCELLATION_REASON_BYTES: usize = 4 * 1024;
/// Maximum number of retained open metadata entries.
pub const MAX_METADATA_ENTRIES: usize = 128;
/// Maximum UTF-8 bytes in an individual metadata key.
pub const MAX_METADATA_KEY_BYTES: usize = 512;
/// Maximum canonical JSON bytes in an individual metadata value.
pub const MAX_METADATA_VALUE_BYTES: usize = 16 * 1024;
/// Maximum UTF-8 bytes in a present pagination cursor.
pub const MAX_CURSOR_BYTES: usize = 4 * 1024;
/// Maximum icon size strings retained from one peer icon.
pub const MAX_ICON_SIZE_ENTRIES: usize = 32;
/// Maximum UTF-8 bytes in an individual peer icon size string.
pub const MAX_ICON_SIZE_BYTES: usize = 128;
/// Maximum encoded bytes in one common binary content payload.
pub const MAX_CONTENT_ENCODED_BYTES: usize = 1024 * 1024;
/// Maximum UTF-8 bytes in each W3C trace field.
pub const MAX_TRACE_FIELD_BYTES: usize = 4 * 1024;

/// A schema-valid RFC 3986 URI with a required ASCII scheme.
///
/// This type deliberately preserves the original wire spelling. It does not fetch, normalize,
/// lowercase, resolve, or otherwise authorize the URI.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AbsoluteUri(String);

impl AbsoluteUri {
    /// Parses an absolute URI without changing its bytes.
    pub fn parse(value: impl Into<String>) -> Result<Self, CommonTypeError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_ABSOLUTE_URI_BYTES {
            return Err(if value.len() > MAX_ABSOLUTE_URI_BYTES {
                CommonTypeError::TooLong("URI")
            } else {
                CommonTypeError::Invalid("absolute URI")
            });
        }
        if !value.is_ascii() || value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f) {
            return Err(CommonTypeError::Invalid("absolute URI"));
        }
        let Some(colon) = value.find(':') else {
            return Err(CommonTypeError::Invalid("URI scheme"));
        };
        let scheme = &value[..colon];
        if scheme.is_empty()
            || !scheme.as_bytes()[0].is_ascii_alphabetic()
            || !scheme
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
            || !valid_percent_escapes(&value)
        {
            return Err(CommonTypeError::Invalid("absolute URI"));
        }
        Ok(Self(value))
    }

    /// Returns the exact schema-valid wire string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the original scheme spelling.
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.0[..self.0.find(':').expect("validated URI has a scheme")]
    }

    /// Tests a scheme with RFC 3986 ASCII-case-insensitive comparison.
    #[must_use]
    pub fn has_scheme(&self, scheme: &str) -> bool {
        self.scheme().eq_ignore_ascii_case(scheme)
    }
}

impl<'de> Deserialize<'de> for AbsoluteUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .and_then(|value| Self::parse(value).map_err(serde::de::Error::custom))
    }
}

fn valid_percent_escapes(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

/// An opaque cursor where only absence means the end of a paginated result set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OpaqueCursor {
    /// The wire field was absent.
    Absent,
    /// The wire field was present, including the valid empty string.
    Present(String),
}

impl OpaqueCursor {
    /// Preserves absent, empty, and nonempty cursor states distinctly.
    #[must_use]
    pub fn from_presence(value: Option<String>) -> Self {
        value.map_or(Self::Absent, Self::Present)
    }

    /// Admits a bounded cursor while preserving absent and empty states.
    pub fn try_from_presence(value: Option<String>) -> Result<Self, CommonTypeError> {
        if value
            .as_ref()
            .is_some_and(|cursor| cursor.len() > MAX_CURSOR_BYTES)
        {
            return Err(CommonTypeError::TooLong("pagination cursor"));
        }
        Ok(Self::from_presence(value))
    }

    /// Returns the present value, if the field occurred on the wire.
    #[must_use]
    pub fn as_present(&self) -> Option<&str> {
        match self {
            Self::Absent => None,
            Self::Present(value) => Some(value),
        }
    }
}

/// Final implementation identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Implementation {
    /// Programmatic implementation name.
    pub name: String,
    /// Implementation version.
    pub version: String,
    /// Optional display title. An empty present title remains present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional, untrusted website identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website_url: Option<AbsoluteUri>,
    /// Optional wire-preserving icon set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icons: Vec<RawIcon>,
}

/// Final MCP logging severities, aligned to RFC 5424 names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingLevel {
    /// Debug diagnostic information.
    Debug,
    /// Informational event.
    Info,
    /// Significant normal event.
    Notice,
    /// Warning event.
    Warning,
    /// Error event.
    Error,
    /// Critical event.
    Critical,
    /// Alert event.
    Alert,
    /// Emergency event.
    Emergency,
}

impl Implementation {
    /// Constructs an implementation identity with required nonempty fields.
    pub fn try_new(
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, CommonTypeError> {
        let name = name.into();
        let version = version.into();
        if name.is_empty() || version.is_empty() {
            return Err(CommonTypeError::Invalid("implementation identity"));
        }
        Ok(Self {
            name,
            version,
            title: None,
            description: None,
            website_url: None,
            icons: Vec::new(),
        })
    }

    /// Returns the effective display name without synthesizing a wire title.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.title.as_deref().unwrap_or(&self.name)
    }
}

/// Open `_meta` values with typed access to final reserved keys.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OpenMetadata(BTreeMap<String, Value>);

impl OpenMetadata {
    /// Validates every key and preserves valid unknown peer entries exactly.
    pub fn try_from_entries(
        entries: impl IntoIterator<Item = (String, Value)>,
    ) -> Result<Self, CommonTypeError> {
        let mut values = BTreeMap::new();
        for (key, value) in entries {
            let value_bytes = serde_json::to_vec(&value)
                .map_err(|_| CommonTypeError::Invalid("metadata value"))?
                .len();
            if values.len() == MAX_METADATA_ENTRIES
                || key.len() > MAX_METADATA_KEY_BYTES
                || value_bytes > MAX_METADATA_VALUE_BYTES
                || !valid_metadata_key(&key)
                || values.insert(key, value).is_some()
            {
                return Err(CommonTypeError::Invalid("metadata key"));
            }
        }
        let metadata = Self(values);
        metadata.validate_reserved_values()?;
        Ok(metadata)
    }

    /// Returns the exact retained entry for a valid unknown key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    /// Returns all retained entries without granting them authority.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<String, Value> {
        &self.0
    }

    /// Reads the typed protocol version, if this metadata role declares it.
    pub fn protocol_version(&self) -> Result<Option<&str>, CommonTypeError> {
        self.optional_string("io.modelcontextprotocol/protocolVersion")
    }

    /// Reads typed client capabilities, if present.
    pub fn client_capabilities(
        &self,
    ) -> Result<Option<&serde_json::Map<String, Value>>, CommonTypeError> {
        match self.0.get("io.modelcontextprotocol/clientCapabilities") {
            None => Ok(None),
            Some(Value::Object(value)) => Ok(Some(value)),
            Some(_) => Err(CommonTypeError::Invalid("client capabilities")),
        }
    }

    /// Decodes the self-reported client identity without treating it as authority.
    pub fn client_info(&self) -> Result<Option<Implementation>, CommonTypeError> {
        self.typed_implementation("io.modelcontextprotocol/clientInfo")
    }

    /// Reads the exact optional logging-level metadata value.
    pub fn log_level(&self) -> Result<Option<LoggingLevel>, CommonTypeError> {
        self.0
            .get("io.modelcontextprotocol/logLevel")
            .map_or(Ok(None), |value| {
                serde_json::from_value(value.clone())
                    .map(Some)
                    .map_err(|_| CommonTypeError::Invalid("logging level metadata"))
            })
    }

    fn optional_string(&self, key: &str) -> Result<Option<&str>, CommonTypeError> {
        match self.0.get(key) {
            None => Ok(None),
            Some(Value::String(value)) => Ok(Some(value)),
            Some(_) => Err(CommonTypeError::Invalid("metadata string")),
        }
    }

    fn typed_implementation(&self, key: &str) -> Result<Option<Implementation>, CommonTypeError> {
        self.0.get(key).map_or(Ok(None), |value| {
            serde_json::from_value(value.clone())
                .map(Some)
                .map_err(|_| CommonTypeError::Invalid("implementation metadata"))
        })
    }

    fn validate_reserved_values(&self) -> Result<(), CommonTypeError> {
        if self.protocol_version()?.is_some() && self.client_capabilities()?.is_none() {
            return Err(CommonTypeError::Invalid("client capabilities"));
        }
        for key in [
            "io.modelcontextprotocol/clientInfo",
            "io.modelcontextprotocol/serverInfo",
        ] {
            if self.0.contains_key(key) && self.typed_implementation(key)?.is_none() {
                return Err(CommonTypeError::Invalid("implementation metadata"));
            }
        }
        let _ = self.log_level()?;
        if let Some(value) = self.0.get("io.modelcontextprotocol/subscriptionId") {
            let valid = matches!(value, Value::String(_))
                || matches!(value, Value::Number(number) if number.as_i64().is_some());
            if !valid {
                return Err(CommonTypeError::Invalid("subscription ID metadata"));
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for OpenMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        BTreeMap::<String, Value>::deserialize(deserializer)
            .and_then(|entries| Self::try_from_entries(entries).map_err(serde::de::Error::custom))
    }
}

fn valid_metadata_key(key: &str) -> bool {
    let (prefix, name) = match key.split_once('/') {
        Some((prefix, name)) if !name.contains('/') => (Some(prefix), name),
        Some(_) => return false,
        None => (None, key),
    };
    if let Some(prefix) = prefix {
        if !valid_reverse_dns_prefix(prefix) {
            return false;
        }
        if prefix == "io.modelcontextprotocol"
            && !matches!(
                name,
                "protocolVersion"
                    | "clientCapabilities"
                    | "clientInfo"
                    | "logLevel"
                    | "serverInfo"
                    | "subscriptionId"
            )
        {
            return false;
        }
    }
    name.is_empty()
        || (name.as_bytes()[0].is_ascii_alphanumeric()
            && name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
}

fn valid_reverse_dns_prefix(prefix: &str) -> bool {
    let labels = prefix.split('.').collect::<Vec<_>>();
    labels.len() >= 2
        && labels.into_iter().all(|label| {
            !label.is_empty()
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// Bounded trace-context fields preserved from open metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TraceContext {
    /// W3C trace parent value.
    pub traceparent: Option<String>,
    /// W3C trace state value.
    pub tracestate: Option<String>,
    /// W3C baggage value.
    pub baggage: Option<String>,
}

impl TraceContext {
    /// Extracts trace fields only when they are strings in valid metadata.
    pub fn try_from_metadata(metadata: &OpenMetadata) -> Result<Self, CommonTypeError> {
        let field = |name| {
            metadata.optional_string(name).and_then(|value| {
                if value.is_some_and(|field| field.len() > MAX_TRACE_FIELD_BYTES) {
                    Err(CommonTypeError::TooLong("trace context"))
                } else {
                    Ok(value.map(ToOwned::to_owned))
                }
            })
        };
        Ok(Self {
            traceparent: field("traceparent")?,
            tracestate: field("tracestate")?,
            baggage: field("baggage")?,
        })
    }
}

/// A peer cancellation request identifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CancellationRequestId {
    /// String JSON-RPC identifier.
    String(String),
    /// Mathematical integer JSON-RPC identifier.
    Integer(i64),
}

/// A bounded peer-provided cancellation reason that deliberately has no raw string accessor,
/// formatter, or serializer.
#[derive(Clone, Eq, PartialEq)]
pub struct UntrustedCancellationReason(String);

/// Final `notifications/cancelled` payload.
#[derive(Clone, Eq, PartialEq)]
pub struct CancellationNotification {
    /// Required non-null request identifier.
    pub request_id: CancellationRequestId,
    reason: Option<UntrustedCancellationReason>,
}

impl CancellationNotification {
    /// Constructs a cancellation payload while bounding an untrusted reason.
    pub fn try_new(
        request_id: CancellationRequestId,
        reason: Option<String>,
    ) -> Result<Self, CommonTypeError> {
        let reason = reason
            .map(|value| {
                if value.len() > MAX_CANCELLATION_REASON_BYTES {
                    Err(CommonTypeError::TooLong("cancellation reason"))
                } else {
                    Ok(UntrustedCancellationReason(value))
                }
            })
            .transpose()?;
        Ok(Self { request_id, reason })
    }

    /// Indicates whether a peer reason was present without rendering or exposing it.
    #[must_use]
    pub fn has_untrusted_reason(&self) -> bool {
        self.reason.is_some()
    }
}

/// Icon theme values admitted by the final schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IconTheme {
    /// An icon designed for a light background.
    Light,
    /// An icon designed for a dark background.
    Dark,
}

/// A raw, structurally valid icon source. Rendering admission is deliberately separate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawIcon {
    /// Required schema URI source.
    pub src: AbsoluteUri,
    /// Optional peer MIME declaration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Presence-aware size strings. Empty is distinct from absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sizes: Option<Vec<String>>,
    /// Optional theme without serialization defaults.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme: Option<IconTheme>,
}

impl RawIcon {
    /// Constructs a raw icon with a required absolute source.
    pub fn try_new(src: impl Into<String>) -> Result<Self, CommonTypeError> {
        Ok(Self {
            src: AbsoluteUri::parse(src)?,
            mime_type: None,
            sizes: None,
            theme: None,
        })
    }

    /// Adds exact wire-preserving optional icon fields with bounded peer sizes.
    pub fn try_with_details(
        src: impl Into<String>,
        mime_type: Option<String>,
        sizes: Option<Vec<String>>,
        theme: Option<IconTheme>,
    ) -> Result<Self, CommonTypeError> {
        if sizes.as_ref().is_some_and(|values| {
            values.len() > MAX_ICON_SIZE_ENTRIES
                || values.iter().any(|value| value.len() > MAX_ICON_SIZE_BYTES)
        }) {
            return Err(CommonTypeError::TooLong("icon sizes"));
        }
        Ok(Self {
            src: AbsoluteUri::parse(src)?,
            mime_type,
            sizes,
            theme,
        })
    }

    /// Returns the documented effective size class without changing wire presence.
    #[must_use]
    pub fn effective_any_size(&self) -> bool {
        self.sizes.is_none()
    }
}

/// Annotation audience values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnnotationAudience {
    /// Intended for a user.
    User,
    /// Intended for an assistant.
    Assistant,
}

/// Optional content annotations.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Annotations {
    /// Intended audience roles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<AnnotationAudience>>,
    /// Finite inclusive priority hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<f64>,
    /// Peer timestamp string preserved without inventing a schema rejection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

impl Annotations {
    /// Validates the only schema-constrained numeric field.
    pub fn try_with_priority(priority: f64) -> Result<Self, CommonTypeError> {
        if !priority.is_finite() || !(0.0..=1.0).contains(&priority) {
            return Err(CommonTypeError::Invalid("annotation priority"));
        }
        Ok(Self {
            priority: Some(priority),
            ..Self::default()
        })
    }
}

/// Link-style content block fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceLink {
    /// Exact resource identity.
    pub uri: AbsoluteUri,
    /// Required display name.
    pub name: String,
    /// Optional link annotations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
    /// Preserved open metadata.
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
}

/// Text or blob resource contents embedded in content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum EmbeddedResourceContents {
    /// Text resource contents.
    Text {
        uri: AbsoluteUri,
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
    },
    /// Blob resource contents.
    Blob {
        uri: AbsoluteUri,
        blob: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
    },
}

/// Final common content discriminators.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Text content.
    Text {
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
        #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
        meta: Option<OpenMetadata>,
    },
    /// Binary image content.
    Image {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
        #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
        meta: Option<OpenMetadata>,
    },
    /// Binary audio content.
    Audio {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
        #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
        meta: Option<OpenMetadata>,
    },
    /// A resource link uses the exact `resource_link` discriminator.
    ResourceLink {
        uri: AbsoluteUri,
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
        #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
        meta: Option<OpenMetadata>,
    },
    /// An embedded resource uses the exact `resource` discriminator.
    Resource {
        resource: EmbeddedResourceContents,
        #[serde(skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
        #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
        meta: Option<OpenMetadata>,
    },
}

impl ContentBlock {
    /// Constructs text content.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text {
            text: text.into(),
            annotations: None,
            meta: None,
        }
    }

    /// Constructs image content after validating base64 and image MIME shape.
    pub fn image(
        data: impl Into<String>,
        mime_type: impl Into<String>,
    ) -> Result<Self, CommonTypeError> {
        let data = data.into();
        let mime_type = mime_type.into();
        valid_binary_content(&data, &mime_type, "image/")?;
        Ok(Self::Image {
            data,
            mime_type,
            annotations: None,
            meta: None,
        })
    }

    /// Constructs audio content after validating base64 and audio MIME shape.
    pub fn audio(
        data: impl Into<String>,
        mime_type: impl Into<String>,
    ) -> Result<Self, CommonTypeError> {
        let data = data.into();
        let mime_type = mime_type.into();
        valid_binary_content(&data, &mime_type, "audio/")?;
        Ok(Self::Audio {
            data,
            mime_type,
            annotations: None,
            meta: None,
        })
    }

    /// Constructs a resource-link content block.
    pub fn resource_link(
        uri: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, CommonTypeError> {
        Ok(Self::ResourceLink {
            uri: AbsoluteUri::parse(uri)?,
            name: name.into(),
            annotations: None,
            meta: None,
        })
    }

    /// Constructs embedded text resource content.
    pub fn resource(
        uri: impl Into<String>,
        text: impl Into<String>,
        mime_type: Option<String>,
    ) -> Result<Self, CommonTypeError> {
        Ok(Self::Resource {
            resource: EmbeddedResourceContents::Text {
                uri: AbsoluteUri::parse(uri)?,
                text: text.into(),
                mime_type,
            },
            annotations: None,
            meta: None,
        })
    }
}

fn valid_binary_content(
    data: &str,
    mime_type: &str,
    required_prefix: &str,
) -> Result<(), CommonTypeError> {
    if data.len() > MAX_CONTENT_ENCODED_BYTES {
        return Err(CommonTypeError::TooLong("binary content"));
    }
    if !mime_type.starts_with(required_prefix) || mime_type.len() == required_prefix.len() {
        return Err(CommonTypeError::Invalid("binary MIME type"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map(|_| ())
        .map_err(|_| CommonTypeError::Invalid("base64 content"))
}

/// Direction of a final common-type wire envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommonWireDirection {
    /// A client or server request.
    Request,
    /// A notification, which has no JSON-RPC response.
    Notification,
    /// A request result.
    Result,
}

/// Structural schema admission for the final common wire slice.
///
/// It validates exact spellings and direction-sensitive metadata without converting peer input
/// into a locally authorized resource, icon, or cancellation action.
#[derive(Clone, Copy, Debug, Default)]
pub struct FinalCommonTypesSchema;

impl FinalCommonTypesSchema {
    /// The exact final-schema URI owners; `Icon.src` has a separately typed raw icon source.
    pub const FINAL_URI_OWNERS: [&'static str; 12] = [
        "BlobResourceContents.uri",
        "ElicitRequestURLParams.url",
        "Icon.src",
        "Implementation.websiteUrl",
        "ReadResourceRequestParams.uri",
        "Resource.uri",
        "ResourceContents.uri",
        "ResourceLink.uri",
        "ResourceRequestParams.uri",
        "ResourceUpdatedNotificationParams.uri",
        "Root.uri",
        "TextResourceContents.uri",
    ];

    /// Validates a final common wire object for its declared direction.
    pub fn validate(direction: CommonWireDirection, wire: &Value) -> Result<(), CommonTypeError> {
        let object = wire
            .as_object()
            .ok_or(CommonTypeError::Invalid("common wire object"))?;
        match (direction, object.get("_meta")) {
            (CommonWireDirection::Request, Some(meta)) => Self::validate_request_metadata(meta)?,
            (CommonWireDirection::Request, None) => {
                return Err(CommonTypeError::Invalid("request metadata"));
            }
            (_, Some(meta)) => Self::validate_open_metadata(meta)?,
            (_, None) => {}
        }
        if let Some(kind) = object.get("type") {
            let kind = kind
                .as_str()
                .ok_or(CommonTypeError::Invalid("content discriminator"))?;
            if !matches!(
                kind,
                "text" | "image" | "audio" | "resource_link" | "resource"
            ) {
                return Err(CommonTypeError::Invalid("content discriminator"));
            }
            let content: ContentBlock = serde_json::from_value(wire.clone())
                .map_err(|_| CommonTypeError::Invalid("content block"))?;
            Self::validate_content(&content)?;
        }
        if object.contains_key("src") {
            let _ = Self::validate_icon(wire)?;
        }
        if object.get("method").and_then(Value::as_str) == Some("notifications/cancelled") {
            if direction != CommonWireDirection::Notification {
                return Err(CommonTypeError::Invalid("cancellation direction"));
            }
            Self::validate_cancellation_params(
                object
                    .get("params")
                    .ok_or(CommonTypeError::Invalid("cancellation params"))?,
            )?;
        }
        Ok(())
    }

    /// Validates the raw icon wire shape while preserving absent versus present-empty sizes.
    pub fn validate_icon(wire: &Value) -> Result<RawIcon, CommonTypeError> {
        let object = wire
            .as_object()
            .ok_or(CommonTypeError::Invalid("icon object"))?;
        for field in ["mimeType", "sizes", "theme"] {
            if object.get(field).is_some_and(Value::is_null) {
                return Err(CommonTypeError::Invalid("icon optional field"));
            }
        }
        let icon: RawIcon =
            serde_json::from_value(wire.clone()).map_err(|_| CommonTypeError::Invalid("icon"))?;
        RawIcon::try_with_details(
            icon.src.as_str(),
            icon.mime_type.clone(),
            icon.sizes.clone(),
            icon.theme,
        )
    }

    /// Produces the deterministic JSON form used by frozen golden-wire records.
    pub fn canonical_json(wire: &Value) -> Result<String, CommonTypeError> {
        serde_json::to_string(wire).map_err(|_| CommonTypeError::Invalid("canonical JSON"))
    }

    /// Validates a wire object and requires its canonical JSON to equal the frozen golden.
    pub fn validate_golden(
        direction: CommonWireDirection,
        wire: &Value,
        golden: &str,
    ) -> Result<(), CommonTypeError> {
        Self::validate(direction, wire)?;
        if Self::canonical_json(wire)? != golden {
            return Err(CommonTypeError::Invalid("golden wire"));
        }
        Ok(())
    }

    fn validate_open_metadata(meta: &Value) -> Result<OpenMetadata, CommonTypeError> {
        let entries = meta
            .as_object()
            .ok_or(CommonTypeError::Invalid("metadata object"))?
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()));
        OpenMetadata::try_from_entries(entries)
    }

    fn validate_request_metadata(meta: &Value) -> Result<(), CommonTypeError> {
        let metadata = Self::validate_open_metadata(meta)?;
        if metadata.protocol_version()?.is_none() || metadata.client_capabilities()?.is_none() {
            return Err(CommonTypeError::Invalid("required request metadata"));
        }
        let _ = metadata.client_info()?;
        let _ = TraceContext::try_from_metadata(&metadata)?;
        Ok(())
    }

    fn validate_content(content: &ContentBlock) -> Result<(), CommonTypeError> {
        match content {
            ContentBlock::Image {
                data,
                mime_type,
                annotations,
                ..
            } => {
                Self::validate_annotations(annotations)?;
                valid_binary_content(data, mime_type, "image/")
            }
            ContentBlock::Audio {
                data,
                mime_type,
                annotations,
                ..
            } => {
                Self::validate_annotations(annotations)?;
                valid_binary_content(data, mime_type, "audio/")
            }
            ContentBlock::ResourceLink {
                uri, annotations, ..
            } => {
                Self::validate_annotations(annotations)?;
                AbsoluteUri::parse(uri.as_str()).map(|_| ())
            }
            ContentBlock::Resource {
                resource,
                annotations,
                ..
            } => {
                Self::validate_annotations(annotations)?;
                match resource {
                    EmbeddedResourceContents::Text { uri, .. }
                    | EmbeddedResourceContents::Blob { uri, .. } => {
                        AbsoluteUri::parse(uri.as_str()).map(|_| ())
                    }
                }
            }
            ContentBlock::Text { annotations, .. } => Self::validate_annotations(annotations),
        }
    }

    fn validate_annotations(annotations: &Option<Annotations>) -> Result<(), CommonTypeError> {
        if annotations
            .as_ref()
            .and_then(|value| value.priority)
            .is_some_and(|priority| !priority.is_finite() || !(0.0..=1.0).contains(&priority))
        {
            return Err(CommonTypeError::Invalid("annotation priority"));
        }
        Ok(())
    }

    fn validate_cancellation_params(params: &Value) -> Result<(), CommonTypeError> {
        let params = params
            .as_object()
            .ok_or(CommonTypeError::Invalid("cancellation params"))?;
        let request_id = params
            .get("requestId")
            .ok_or(CommonTypeError::Invalid("cancellation request ID"))?;
        let request_id = match request_id {
            Value::String(value) => CancellationRequestId::String(value.clone()),
            Value::Number(value) if value.as_i64().is_some() => {
                CancellationRequestId::Integer(value.as_i64().expect("checked integer"))
            }
            _ => return Err(CommonTypeError::Invalid("cancellation request ID")),
        };
        let reason = match params.get("reason") {
            None => None,
            Some(Value::String(value)) => Some(value.clone()),
            Some(_) => return Err(CommonTypeError::Invalid("cancellation reason")),
        };
        let _ = CancellationNotification::try_new(request_id, reason)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn prt_02_a_positive() {
        let implementation = Implementation::try_new("fastmcp", "0.1.0").expect("implementation");
        let metadata = OpenMetadata::try_from_entries([
            ("".to_owned(), json!("empty name is valid")),
            ("com.example/".to_owned(), json!({"future": true})),
            (
                "io.modelcontextprotocol/protocolVersion".to_owned(),
                json!("2026-07-28"),
            ),
            (
                "io.modelcontextprotocol/clientCapabilities".to_owned(),
                json!({}),
            ),
            (
                "io.modelcontextprotocol/clientInfo".to_owned(),
                serde_json::to_value(&implementation).expect("identity JSON"),
            ),
            (
                "traceparent".to_owned(),
                json!("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"),
            ),
        ])
        .expect("metadata");
        assert_eq!(
            metadata.protocol_version().expect("version"),
            Some("2026-07-28")
        );
        assert_eq!(
            TraceContext::try_from_metadata(&metadata)
                .expect("trace")
                .traceparent
                .as_deref(),
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
        );

        let icon = RawIcon::try_new("https://example.test/icon.png?variant=1#exact").expect("icon");
        assert!(icon.effective_any_size());
        assert_eq!(
            OpaqueCursor::from_presence(Some(String::new())).as_present(),
            Some("")
        );
        let content = ContentBlock::image("aGVsbG8=", "image/png").expect("image");
        let encoded = serde_json::to_value(&content).expect("serialize content");
        assert_eq!(encoded["type"], "image");
        assert_eq!(
            serde_json::from_value::<ContentBlock>(encoded).expect("round trip"),
            content
        );
    }

    #[test]
    fn prt_02_a_planted_negative() {
        let accepted = OpenMetadata::try_from_entries([(
            "com.example/valid".to_owned(),
            json!({"kept": true}),
        )])
        .expect("accepted baseline");
        let baseline = accepted.clone();
        let rejection = OpenMetadata::try_from_entries([(
            "com..example/valid".to_owned(),
            json!({"kept": true}),
        )]);
        assert_eq!(rejection, Err(CommonTypeError::Invalid("metadata key")));
        assert_eq!(
            accepted, baseline,
            "the rejected one-variable key change cannot mutate accepted state"
        );
    }

    #[test]
    fn prt_02_b_positive() {
        let request = json!({
            "_meta": {
                "com.example/future": {"nullIsData": null},
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"
            }
        });
        FinalCommonTypesSchema::validate(CommonWireDirection::Request, &request)
            .expect("request metadata schema");
        let golden = "{\"_meta\":{\"com.example/future\":{\"nullIsData\":null},\"io.modelcontextprotocol/clientCapabilities\":{},\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"traceparent\":\"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00\"}}";
        assert_eq!(
            FinalCommonTypesSchema::canonical_json(&request).expect("canonical JSON"),
            golden
        );
        FinalCommonTypesSchema::validate_golden(CommonWireDirection::Request, &request, golden)
            .expect("exact request golden");

        let content = ContentBlock::image("aGVsbG8=", "image/png").expect("image content");
        let wire = serde_json::to_value(&content).expect("content wire");
        FinalCommonTypesSchema::validate(CommonWireDirection::Result, &wire)
            .expect("content schema");
        assert_eq!(wire["type"], "image");
        assert_eq!(
            serde_json::from_value::<ContentBlock>(wire).expect("content round trip"),
            content
        );
        assert_eq!(
            OpaqueCursor::try_from_presence(Some(String::new()))
                .expect("bounded empty cursor")
                .as_present(),
            Some("")
        );
        let icon = json!({
            "src": "HTTPS://example.test/icon.svg?variant=1",
            "sizes": [],
            "theme": "dark"
        });
        let icon = FinalCommonTypesSchema::validate_icon(&icon).expect("icon schema");
        assert!(
            !icon.effective_any_size(),
            "present empty sizes stay present"
        );
        let cancellation = json!({
            "method": "notifications/cancelled",
            "params": {"requestId": 9, "reason": "bounded"}
        });
        FinalCommonTypesSchema::validate(CommonWireDirection::Notification, &cancellation)
            .expect("notification-only cancellation");
        let bounded_cursor = OpaqueCursor::try_from_presence(Some("x".repeat(MAX_CURSOR_BYTES)))
            .expect("cursor at exact bound");
        assert_eq!(
            bounded_cursor.as_present().map(str::len),
            Some(MAX_CURSOR_BYTES)
        );
        assert_eq!(FinalCommonTypesSchema::FINAL_URI_OWNERS.len(), 12);
    }

    #[test]
    fn prt_02_b_planted_negative() {
        let accepted = json!({
            "_meta": {
                "com.example/future": {"kept": true},
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/protocolVersion": "2026-07-28"
            }
        });
        FinalCommonTypesSchema::validate(CommonWireDirection::Request, &accepted)
            .expect("accepted baseline");
        let baseline = accepted.clone();
        let mut planted = accepted.clone();
        let meta = planted
            .get_mut("_meta")
            .and_then(Value::as_object_mut)
            .expect("metadata object");
        let preserved = meta
            .remove("com.example/future")
            .expect("one valid open key");
        meta.insert("io.modelcontextprotocol/future".to_owned(), preserved);
        assert_eq!(
            FinalCommonTypesSchema::validate(CommonWireDirection::Request, &planted),
            Err(CommonTypeError::Invalid("metadata key"))
        );
        assert_eq!(
            accepted, baseline,
            "the one-key rejection cannot mutate retained wire state"
        );
    }
}
