//! MCP protocol types.
//!
//! Core types used in MCP communication.

use std::collections::BTreeMap;

use crate::common_types::{AbsoluteUri, Annotations, OpenMetadata, RawIcon, SamplingContentBlock};
use base64::Engine as _;
use serde::de::Error as _;
use serde::{Deserialize, Serialize};

/// MCP protocol version.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Server capabilities advertised during initialization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// Tool-related capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
    /// Resource-related capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    /// Prompt-related capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,
    /// Logging capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<LoggingCapability>,
    /// Background tasks capability (Docket/SEP-1686).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tasks: Option<TasksCapability>,
}

/// Tool capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolsCapability {
    /// Whether the server supports tool list changes.
    #[serde(
        default,
        rename = "listChanged",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub list_changed: bool,
}

/// Resource capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourcesCapability {
    /// Whether the server supports resource subscriptions.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub subscribe: bool,
    /// Whether the server supports resource list changes.
    #[serde(
        default,
        rename = "listChanged",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub list_changed: bool,
}

/// Prompt capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptsCapability {
    /// Whether the server supports prompt list changes.
    #[serde(
        default,
        rename = "listChanged",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub list_changed: bool,
}

/// Logging capability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoggingCapability {}

/// Client capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientCapabilities {
    /// Sampling capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<SamplingCapability>,
    /// Elicitation capability (user input requests).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elicitation: Option<ElicitationCapability>,
    /// Roots capability (filesystem roots).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roots: Option<RootsCapability>,
}

/// Sampling capability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SamplingCapability {}

/// Capability for form mode elicitation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FormElicitationCapability {}

/// Capability for URL mode elicitation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UrlElicitationCapability {}

/// Elicitation capability.
///
/// Clients must support at least one mode (form or url).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ElicitationCapability {
    /// Present if the client supports form mode elicitation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form: Option<FormElicitationCapability>,
    /// Present if the client supports URL mode elicitation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<UrlElicitationCapability>,
}

impl ElicitationCapability {
    /// Creates a form-mode elicitation capability.
    #[must_use]
    pub fn form() -> Self {
        Self {
            form: Some(FormElicitationCapability {}),
            url: None,
        }
    }

    /// Creates a URL-mode elicitation capability.
    #[must_use]
    pub fn url() -> Self {
        Self {
            form: None,
            url: Some(UrlElicitationCapability {}),
        }
    }

    /// Creates an elicitation capability supporting both modes.
    #[must_use]
    pub fn both() -> Self {
        Self {
            form: Some(FormElicitationCapability {}),
            url: Some(UrlElicitationCapability {}),
        }
    }

    /// Returns true if form mode is supported.
    #[must_use]
    pub fn supports_form(&self) -> bool {
        self.form.is_some()
    }

    /// Returns true if URL mode is supported.
    #[must_use]
    pub fn supports_url(&self) -> bool {
        self.url.is_some()
    }
}

/// Roots capability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RootsCapability {
    /// Whether the client supports list changes notifications.
    #[serde(
        rename = "listChanged",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub list_changed: bool,
}

/// A root definition representing a filesystem location.
///
/// Roots define the boundaries of where servers can operate within the filesystem,
/// allowing them to understand which directories and files they have access to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Root {
    /// Unique identifier for the root. Must be a `file://` URI.
    pub uri: String,
    /// Optional human-readable name for display purposes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Root {
    /// Creates a new root with the given URI.
    #[must_use]
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            name: None,
        }
    }

    /// Creates a new root with a name.
    #[must_use]
    pub fn with_name(uri: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            name: Some(name.into()),
        }
    }
}

/// Server information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Server name.
    pub name: String,
    /// Server version.
    pub version: String,
}

/// Client information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Client name.
    pub name: String,
    /// Client version.
    pub version: String,
}

// ============================================================================
// Icon Metadata
// ============================================================================

/// Icon metadata for visual representation of components.
///
/// Icons provide visual representation for tools, resources, and prompts
/// in client UIs. All fields are optional to support various use cases.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Icon {
    /// URL or data URI for the icon.
    ///
    /// Can be:
    /// - HTTP/HTTPS URL: `https://example.com/icon.png`
    /// - Data URI: `data:image/png;base64,iVBORw0KGgo...`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,

    /// MIME type of the icon (e.g., "image/png", "image/svg+xml").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,

    /// Size hints for the icon (e.g., "32x32", "16x16 32x32 64x64").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sizes: Option<String>,
}

impl Icon {
    /// Creates a new icon with just a source URL.
    #[must_use]
    pub fn new(src: impl Into<String>) -> Self {
        Self {
            src: Some(src.into()),
            mime_type: None,
            sizes: None,
        }
    }

    /// Creates a new icon with source and MIME type.
    #[must_use]
    pub fn with_mime_type(src: impl Into<String>, mime_type: impl Into<String>) -> Self {
        Self {
            src: Some(src.into()),
            mime_type: Some(mime_type.into()),
            sizes: None,
        }
    }

    /// Creates a new icon with all fields.
    #[must_use]
    pub fn full(
        src: impl Into<String>,
        mime_type: impl Into<String>,
        sizes: impl Into<String>,
    ) -> Self {
        Self {
            src: Some(src.into()),
            mime_type: Some(mime_type.into()),
            sizes: Some(sizes.into()),
        }
    }

    /// Returns true if this icon has a source.
    #[must_use]
    pub fn has_src(&self) -> bool {
        self.src.is_some()
    }

    /// Returns true if the source is a data URI.
    #[must_use]
    pub fn is_data_uri(&self) -> bool {
        self.src.as_ref().is_some_and(|s| s.starts_with("data:"))
    }
}

// ============================================================================
// Component Definitions
// ============================================================================

/// Tool annotations for additional metadata.
///
/// These annotations provide hints about tool behavior to help clients
/// make informed decisions about tool usage.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolAnnotations {
    /// Whether the tool may cause destructive side effects.
    /// True means the tool modifies external state (e.g., deleting files).
    /// Serialized as the MCP-spec `destructiveHint` field.
    #[serde(rename = "destructiveHint", skip_serializing_if = "Option::is_none")]
    pub destructive: Option<bool>,
    /// Whether the tool is idempotent (safe to retry without side effects).
    /// True means calling the tool multiple times has the same effect as calling it once.
    /// Serialized as the MCP-spec `idempotentHint` field.
    #[serde(rename = "idempotentHint", skip_serializing_if = "Option::is_none")]
    pub idempotent: Option<bool>,
    /// Whether the tool is read-only (has no side effects).
    /// True means the tool only reads data without modifying anything.
    /// Serialized as the MCP-spec `readOnlyHint` field.
    #[serde(rename = "readOnlyHint", skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    /// Whether the tool interacts with an "open world" of external entities.
    /// Per the MCP spec `openWorldHint` is a boolean: `true` if the tool may reach
    /// external/unknown systems, `false` if it operates over a closed/local domain.
    #[serde(rename = "openWorldHint", skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

impl ToolAnnotations {
    /// Creates a new empty annotations struct.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the destructive annotation.
    #[must_use]
    pub fn destructive(mut self, value: bool) -> Self {
        self.destructive = Some(value);
        self
    }

    /// Sets the idempotent annotation.
    #[must_use]
    pub fn idempotent(mut self, value: bool) -> Self {
        self.idempotent = Some(value);
        self
    }

    /// Sets the read_only annotation.
    #[must_use]
    pub fn read_only(mut self, value: bool) -> Self {
        self.read_only = Some(value);
        self
    }

    /// Sets the open_world_hint annotation.
    ///
    /// Per the MCP spec `openWorldHint` is a boolean: `true` if the tool interacts
    /// with an open world of external entities, `false` for a closed/local domain.
    #[must_use]
    pub fn open_world_hint(mut self, value: bool) -> Self {
        self.open_world_hint = Some(value);
        self
    }

    /// Returns true if any annotation is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.destructive.is_none()
            && self.idempotent.is_none()
            && self.read_only.is_none()
            && self.open_world_hint.is_none()
    }
}

/// Tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    /// Tool name.
    pub name: String,
    /// Tool description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Input schema (JSON Schema).
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
    /// Output schema (JSON Schema) describing the tool's result structure.
    #[serde(rename = "outputSchema", skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    /// Icon for visual representation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<Icon>,
    /// Component version (semver-like string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Tags for filtering and organization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Tool annotations providing behavioral hints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

/// Resource definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    /// Resource URI.
    pub uri: String,
    /// Resource name.
    pub name: String,
    /// Resource description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type.
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Icon for visual representation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<Icon>,
    /// Component version (semver-like string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Tags for filtering and organization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Resource template definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceTemplate {
    /// URI template (RFC 6570).
    #[serde(rename = "uriTemplate")]
    pub uri_template: String,
    /// Template name.
    pub name: String,
    /// Template description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type.
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Icon for visual representation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<Icon>,
    /// Component version (semver-like string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Tags for filtering and organization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Prompt definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prompt {
    /// Prompt name.
    pub name: String,
    /// Prompt description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Prompt arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
    /// Icon for visual representation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<Icon>,
    /// Component version (semver-like string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Tags for filtering and organization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Prompt argument definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    /// Argument name.
    pub name: String,
    /// Argument description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the argument is required.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
}

// ============================================================================
// Final component definitions
// ============================================================================

/// Shared final component identity fields.
///
/// The final protocol separates a stable programmatic `name` from an optional
/// user-facing `title`. Legacy component definitions deliberately remain
/// separate because their icon, version, and tag members are not final wire
/// members.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalBaseMetadata {
    /// Programmatic component identifier.
    pub name: String,
    /// Optional human-facing display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// Final tool annotations, including the final display-title hint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalToolAnnotations {
    /// Optional display title, lower priority than the enclosing tool title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Whether the tool may perform destructive updates.
    #[serde(
        rename = "destructiveHint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub destructive: Option<bool>,
    /// Whether repeated calls are idempotent.
    #[serde(
        rename = "idempotentHint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub idempotent: Option<bool>,
    /// Whether the tool is read-only.
    #[serde(
        rename = "readOnlyHint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub read_only: Option<bool>,
    /// Whether the tool may interact with an open world.
    #[serde(
        rename = "openWorldHint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub open_world_hint: Option<bool>,
}

/// Exact final `Tool` model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalTool {
    /// Programmatic component identifier.
    pub name: String,
    /// Optional human-facing display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional sized icon collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icons: Option<Vec<RawIcon>>,
    /// Required JSON Schema object for tool input.
    #[serde(
        rename = "inputSchema",
        deserialize_with = "deserialize_final_tool_input_schema"
    )]
    pub input_schema: serde_json::Value,
    /// Optional JSON Schema object for structured tool output.
    #[serde(
        rename = "outputSchema",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_final_json_object"
    )]
    pub output_schema: Option<serde_json::Value>,
    /// Optional behavioral and display hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<FinalToolAnnotations>,
    /// Optional final metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
}

/// Exact final `Resource` model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalResource {
    /// Exact resource URI.
    pub uri: AbsoluteUri,
    /// Programmatic resource identifier.
    pub name: String,
    /// Optional human-facing display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional sized icon collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icons: Option<Vec<RawIcon>>,
    /// Optional resource MIME type.
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Optional raw content size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    /// Optional client-facing annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
    /// Optional final metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
}

/// Exact final `ResourceTemplate` model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalResourceTemplate {
    /// RFC 6570 resource URI template.
    #[serde(rename = "uriTemplate")]
    pub uri_template: String,
    /// Programmatic template identifier.
    pub name: String,
    /// Optional human-facing display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional sized icon collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icons: Option<Vec<RawIcon>>,
    /// Optional MIME type for resources matched by the template.
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Optional client-facing annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
    /// Optional final metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
}

/// Exact final prompt-argument model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalPromptArgument {
    /// Programmatic argument identifier.
    pub name: String,
    /// Optional human-facing display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether an argument is required; absence remains distinct from false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// Exact final `Prompt` model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalPrompt {
    /// Programmatic prompt identifier.
    pub name: String,
    /// Optional human-facing display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional sized icon collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icons: Option<Vec<RawIcon>>,
    /// Optional prompt arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<FinalPromptArgument>>,
    /// Optional final metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
}

fn deserialize_final_tool_input_schema<'de, D>(
    deserializer: D,
) -> Result<serde_json::Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    let Some(object) = value.as_object() else {
        return Err(D::Error::custom("final tool inputSchema must be an object"));
    };
    if object.get("type").and_then(serde_json::Value::as_str) != Some("object") {
        return Err(D::Error::custom(
            "final tool inputSchema must declare type object",
        ));
    }
    Ok(value)
}

fn deserialize_optional_final_json_object<'de, D>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if !value.is_object() {
        return Err(D::Error::custom(
            "final tool outputSchema must be an object",
        ));
    }
    Ok(Some(value))
}

/// Legacy 2024 metadata, retained exactly as an open JSON object.
///
/// The 2024-11-05 schema permits arbitrary JSON members in result `_meta`
/// objects. This intentionally remains distinct from the final-era
/// [`OpenMetadata`] policy.
pub type LegacyMetadata = BTreeMap<String, serde_json::Value>;

/// Exact 2024-11-05 content blocks carried in legacy results.
///
/// The legacy `Content` surface remains available to 2026 adapters. This
/// separate wire model preserves the annotations, `_meta`, and open members
/// that the checked-in 2024 schema permits, while deliberately excluding audio
/// from the legacy content union.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum LegacyContent {
    /// Text content.
    Text {
        /// The text content.
        text: String,
        /// Optional presentation annotations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
        /// Other schema-allowed content members, including an open `_meta` value.
        #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
        additional: BTreeMap<String, serde_json::Value>,
    },
    /// Image content.
    Image {
        /// Base64-encoded image data.
        data: String,
        /// MIME type (e.g., `image/png`).
        #[serde(rename = "mimeType")]
        mime_type: String,
        /// Optional presentation annotations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
        /// Other schema-allowed content members, including an open `_meta` value.
        #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
        additional: BTreeMap<String, serde_json::Value>,
    },
    /// An embedded resource.
    Resource {
        /// Resource contents.
        resource: LegacyResourceContent,
        /// Optional presentation annotations.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Annotations>,
        /// Other schema-allowed content members, including an open `_meta` value.
        #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
        additional: BTreeMap<String, serde_json::Value>,
    },
}

/// Exact 2024-11-05 resource contents carried by legacy results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LegacyResourceContent {
    /// Text resource contents.
    Text {
        /// Resource URI.
        uri: String,
        /// Resource text.
        text: String,
        /// Optional MIME type.
        #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        /// Other schema-allowed resource members, including an open `_meta` value.
        #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
        additional: BTreeMap<String, serde_json::Value>,
    },
    /// Binary resource contents.
    Blob {
        /// Resource URI.
        uri: String,
        /// Base64-encoded resource data.
        blob: String,
        /// Optional MIME type.
        #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        /// Other schema-allowed resource members, including an open `_meta` value.
        #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
        additional: BTreeMap<String, serde_json::Value>,
    },
}

/// Content types used by the broader server and 2026 adapter surfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Content {
    /// Text content.
    Text {
        /// The text content.
        text: String,
    },
    /// Image content.
    Image {
        /// Base64-encoded image data.
        data: String,
        /// MIME type (e.g., "image/png").
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
    /// Audio content.
    Audio {
        /// Base64-encoded audio data.
        data: String,
        /// MIME type (e.g., "audio/wav").
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
    /// Resource content.
    Resource {
        /// The resource being referenced.
        resource: ResourceContent,
    },
}

impl Content {
    /// Creates text content.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }

    /// Creates image content from base64-encoded data.
    #[must_use]
    pub fn image_base64(data: impl Into<String>, mime_type: impl Into<String>) -> Self {
        Self::Image {
            data: data.into(),
            mime_type: mime_type.into(),
        }
    }

    /// Creates image content from raw bytes (base64-encodes internally).
    #[must_use]
    pub fn image_bytes(bytes: impl AsRef<[u8]>, mime_type: impl Into<String>) -> Self {
        let data = base64::engine::general_purpose::STANDARD.encode(bytes.as_ref());
        Self::image_base64(data, mime_type)
    }

    /// Creates audio content from base64-encoded data.
    #[must_use]
    pub fn audio_base64(data: impl Into<String>, mime_type: impl Into<String>) -> Self {
        Self::Audio {
            data: data.into(),
            mime_type: mime_type.into(),
        }
    }

    /// Creates audio content from raw bytes (base64-encodes internally).
    #[must_use]
    pub fn audio_bytes(bytes: impl AsRef<[u8]>, mime_type: impl Into<String>) -> Self {
        let data = base64::engine::general_purpose::STANDARD.encode(bytes.as_ref());
        Self::audio_base64(data, mime_type)
    }

    /// Creates an embedded resource content with text payload.
    #[must_use]
    pub fn resource_text(
        uri: impl Into<String>,
        mime_type: Option<String>,
        text: impl Into<String>,
    ) -> Self {
        Self::Resource {
            resource: ResourceContent {
                uri: uri.into(),
                mime_type,
                text: Some(text.into()),
                blob: None,
            },
        }
    }

    /// Creates an embedded resource content with base64 blob payload.
    #[must_use]
    pub fn resource_blob_base64(
        uri: impl Into<String>,
        mime_type: Option<String>,
        blob: impl Into<String>,
    ) -> Self {
        Self::Resource {
            resource: ResourceContent {
                uri: uri.into(),
                mime_type,
                text: None,
                blob: Some(blob.into()),
            },
        }
    }

    /// Creates an embedded resource content with raw bytes payload (base64-encodes internally).
    #[must_use]
    pub fn resource_blob_bytes(
        uri: impl Into<String>,
        mime_type: Option<String>,
        bytes: impl AsRef<[u8]>,
    ) -> Self {
        let blob = base64::engine::general_purpose::STANDARD.encode(bytes.as_ref());
        Self::resource_blob_base64(uri, mime_type, blob)
    }
}

/// Resource content in a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceContent {
    /// Resource URI.
    pub uri: String,
    /// MIME type.
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Text content (if text).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Binary content (if blob, base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

/// Role in prompt messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// User role.
    User,
    /// Assistant role.
    Assistant,
}

/// Exact 2024-11-05 prompt messages carried in legacy results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LegacyPromptMessage {
    /// Message role.
    pub role: Role,
    /// Exact legacy message content.
    pub content: LegacyContent,
    /// Other schema-allowed message members, including an open `_meta` value.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// A message in a prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptMessage {
    /// Message role.
    pub role: Role,
    /// Message content.
    pub content: Content,
}

// ============================================================================
// Background Tasks (Docket/SEP-1686)
// ============================================================================

/// Task identifier.
///
/// Unique identifier for background tasks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskId(pub String);

impl TaskId {
    /// Creates a new random task ID.
    #[must_use]
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self(format!("task-{timestamp:x}"))
    }

    /// Creates a task ID from a string.
    #[must_use]
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Returns the task ID as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for TaskId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for TaskId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for TaskId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// Status of a background task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    /// Task is queued but not yet started.
    Pending,
    /// Task is currently running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task failed with an error.
    Failed,
    /// Task was cancelled.
    Cancelled,
}

impl TaskStatus {
    /// Returns true if the task is in a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
        )
    }

    /// Returns true if the task is still active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, TaskStatus::Pending | TaskStatus::Running)
    }
}

/// Information about a background task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    /// Unique task identifier.
    pub id: TaskId,
    /// Task type (identifies the kind of work).
    #[serde(rename = "taskType")]
    pub task_type: String,
    /// Current status.
    pub status: TaskStatus,
    /// Progress (0.0 to 1.0, if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<f64>,
    /// Progress message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Task creation timestamp (ISO 8601).
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// Task start timestamp (ISO 8601), if started.
    #[serde(rename = "startedAt", skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// Task completion timestamp (ISO 8601), if completed.
    #[serde(rename = "completedAt", skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Task result payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    /// Task identifier.
    pub id: TaskId,
    /// Whether the task succeeded.
    pub success: bool,
    /// Result data (if successful).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Error message (if failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Task capability for server capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TasksCapability {
    /// Whether the server supports task list changes notifications.
    #[serde(
        default,
        rename = "listChanged",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub list_changed: bool,
}

// ============================================================================
// Sampling Protocol Types
// ============================================================================

/// Message content for sampling requests.
///
/// Can contain text, images, or tool-related content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SamplingContent {
    /// Text content.
    Text {
        /// The text content.
        text: String,
    },
    /// Image content.
    Image {
        /// Base64-encoded image data.
        data: String,
        /// MIME type (e.g., "image/png").
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
}

/// A message in a sampling conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingMessage {
    /// Message role (user or assistant).
    pub role: Role,
    /// Message content.
    pub content: SamplingContent,
}

impl SamplingMessage {
    /// Creates a new user message with text content.
    #[must_use]
    pub fn user(text: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: SamplingContent::Text { text: text.into() },
        }
    }

    /// Creates a new assistant message with text content.
    #[must_use]
    pub fn assistant(text: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: SamplingContent::Text { text: text.into() },
        }
    }
}

/// Final sampling-specific content block.
pub type FinalSamplingMessageContentBlock = SamplingContentBlock;

/// Exact final sampling-message content, preserving one block versus an array
/// of blocks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FinalSamplingMessageContent {
    /// One sampled content block.
    Block(FinalSamplingMessageContentBlock),
    /// Multiple sampled content blocks.
    Blocks(Vec<FinalSamplingMessageContentBlock>),
}

/// A final sampling conversation message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalSamplingMessage {
    /// Sender role.
    pub role: Role,
    /// Exact final sampling content shape.
    pub content: FinalSamplingMessageContent,
    /// Optional metadata retained on the final wire.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
}

/// Tool-selection mode for final sampling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FinalToolChoiceMode {
    /// The model decides whether to use tools.
    Auto,
    /// The model must use at least one tool.
    Required,
    /// The model must not use tools.
    None,
}

/// Tool-selection controls for final sampling.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalToolChoice {
    /// Optional mode; absence keeps the wire default of `auto` distinct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<FinalToolChoiceMode>,
}

/// Model preferences for sampling requests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelPreferences {
    /// Hints for model selection (model names or patterns).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<ModelHint>,
    /// Priority for cost (0.0 = lowest priority, 1.0 = highest).
    #[serde(rename = "costPriority", skip_serializing_if = "Option::is_none")]
    pub cost_priority: Option<f64>,
    /// Priority for speed (0.0 = lowest priority, 1.0 = highest).
    #[serde(rename = "speedPriority", skip_serializing_if = "Option::is_none")]
    pub speed_priority: Option<f64>,
    /// Priority for intelligence (0.0 = lowest priority, 1.0 = highest).
    #[serde(
        rename = "intelligencePriority",
        skip_serializing_if = "Option::is_none"
    )]
    pub intelligence_priority: Option<f64>,
}

/// A hint for model selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelHint {
    /// Model name or pattern.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Stop reason for sampling responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StopReason {
    /// End of natural turn.
    #[default]
    EndTurn,
    /// Hit stop sequence.
    StopSequence,
    /// Hit max tokens limit.
    MaxTokens,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ========================================================================
    // ServerCapabilities Tests
    // ========================================================================

    #[test]
    fn server_capabilities_default_serialization() {
        let caps = ServerCapabilities::default();
        let value = serde_json::to_value(&caps).expect("serialize");
        // All None fields should be omitted
        assert_eq!(value, json!({}));
    }

    #[test]
    fn server_capabilities_full_serialization() {
        let caps = ServerCapabilities {
            tools: Some(ToolsCapability { list_changed: true }),
            resources: Some(ResourcesCapability {
                subscribe: true,
                list_changed: true,
            }),
            prompts: Some(PromptsCapability { list_changed: true }),
            logging: Some(LoggingCapability {}),
            tasks: Some(TasksCapability { list_changed: true }),
        };
        let value = serde_json::to_value(&caps).expect("serialize");
        assert_eq!(value["tools"]["listChanged"], true);
        assert_eq!(value["resources"]["subscribe"], true);
        assert_eq!(value["resources"]["listChanged"], true);
        assert_eq!(value["prompts"]["listChanged"], true);
        assert!(value.get("logging").is_some());
        assert_eq!(value["tasks"]["listChanged"], true);
    }

    #[test]
    fn server_capabilities_partial_serialization() {
        let caps = ServerCapabilities {
            tools: Some(ToolsCapability::default()),
            ..Default::default()
        };
        let value = serde_json::to_value(&caps).expect("serialize");
        assert!(value.get("tools").is_some());
        assert!(value.get("resources").is_none());
        assert!(value.get("prompts").is_none());
        assert!(value.get("logging").is_none());
        assert!(value.get("tasks").is_none());
    }

    #[test]
    fn server_capabilities_round_trip() {
        let caps = ServerCapabilities {
            tools: Some(ToolsCapability { list_changed: true }),
            resources: Some(ResourcesCapability {
                subscribe: false,
                list_changed: true,
            }),
            prompts: None,
            logging: Some(LoggingCapability {}),
            tasks: None,
        };
        let json_str = serde_json::to_string(&caps).expect("serialize");
        let deserialized: ServerCapabilities =
            serde_json::from_str(&json_str).expect("deserialize");
        assert!(deserialized.tools.is_some());
        assert!(deserialized.tools.as_ref().unwrap().list_changed);
        assert!(deserialized.resources.is_some());
        assert!(!deserialized.resources.as_ref().unwrap().subscribe);
        assert!(deserialized.prompts.is_none());
        assert!(deserialized.logging.is_some());
        assert!(deserialized.tasks.is_none());
    }

    // ========================================================================
    // ToolsCapability Tests
    // ========================================================================

    #[test]
    fn tools_capability_default_omits_false() {
        let cap = ToolsCapability::default();
        let value = serde_json::to_value(&cap).expect("serialize");
        // list_changed defaults to false and should be omitted
        assert!(value.get("listChanged").is_none());
    }

    #[test]
    fn tools_capability_list_changed() {
        let cap = ToolsCapability { list_changed: true };
        let value = serde_json::to_value(&cap).expect("serialize");
        assert_eq!(value["listChanged"], true);
    }

    // ========================================================================
    // ResourcesCapability Tests
    // ========================================================================

    #[test]
    fn resources_capability_default() {
        let cap = ResourcesCapability::default();
        let value = serde_json::to_value(&cap).expect("serialize");
        assert!(value.get("subscribe").is_none());
        assert!(value.get("listChanged").is_none());
    }

    #[test]
    fn resources_capability_full() {
        let cap = ResourcesCapability {
            subscribe: true,
            list_changed: true,
        };
        let value = serde_json::to_value(&cap).expect("serialize");
        assert_eq!(value["subscribe"], true);
        assert_eq!(value["listChanged"], true);
    }

    // ========================================================================
    // ClientCapabilities Tests
    // ========================================================================

    #[test]
    fn client_capabilities_default_serialization() {
        let caps = ClientCapabilities::default();
        let value = serde_json::to_value(&caps).expect("serialize");
        assert_eq!(value, json!({}));
    }

    #[test]
    fn client_capabilities_full_serialization() {
        let caps = ClientCapabilities {
            sampling: Some(SamplingCapability {}),
            elicitation: Some(ElicitationCapability::both()),
            roots: Some(RootsCapability { list_changed: true }),
        };
        let value = serde_json::to_value(&caps).expect("serialize");
        assert!(value.get("sampling").is_some());
        assert!(value.get("elicitation").is_some());
        assert_eq!(value["roots"]["listChanged"], true);
    }

    #[test]
    fn client_capabilities_round_trip() {
        let caps = ClientCapabilities {
            sampling: Some(SamplingCapability {}),
            elicitation: None,
            roots: Some(RootsCapability {
                list_changed: false,
            }),
        };
        let json_str = serde_json::to_string(&caps).expect("serialize");
        let deserialized: ClientCapabilities =
            serde_json::from_str(&json_str).expect("deserialize");
        assert!(deserialized.sampling.is_some());
        assert!(deserialized.elicitation.is_none());
        assert!(deserialized.roots.is_some());
    }

    // ========================================================================
    // ElicitationCapability Tests
    // ========================================================================

    #[test]
    fn elicitation_capability_form_only() {
        let cap = ElicitationCapability::form();
        assert!(cap.supports_form());
        assert!(!cap.supports_url());
        let value = serde_json::to_value(&cap).expect("serialize");
        assert!(value.get("form").is_some());
        assert!(value.get("url").is_none());
    }

    #[test]
    fn elicitation_capability_url_only() {
        let cap = ElicitationCapability::url();
        assert!(!cap.supports_form());
        assert!(cap.supports_url());
    }

    #[test]
    fn elicitation_capability_both() {
        let cap = ElicitationCapability::both();
        assert!(cap.supports_form());
        assert!(cap.supports_url());
    }

    // ========================================================================
    // ServerInfo / ClientInfo Tests
    // ========================================================================

    #[test]
    fn server_info_serialization() {
        let info = ServerInfo {
            name: "test-server".to_string(),
            version: "1.0.0".to_string(),
        };
        let value = serde_json::to_value(&info).expect("serialize");
        assert_eq!(value["name"], "test-server");
        assert_eq!(value["version"], "1.0.0");
    }

    #[test]
    fn client_info_serialization() {
        let info = ClientInfo {
            name: "test-client".to_string(),
            version: "0.1.0".to_string(),
        };
        let value = serde_json::to_value(&info).expect("serialize");
        assert_eq!(value["name"], "test-client");
        assert_eq!(value["version"], "0.1.0");
    }

    // ========================================================================
    // Icon Tests
    // ========================================================================

    #[test]
    fn icon_new() {
        let icon = Icon::new("https://example.com/icon.png");
        assert!(icon.has_src());
        assert!(!icon.is_data_uri());
        assert!(icon.mime_type.is_none());
        assert!(icon.sizes.is_none());
    }

    #[test]
    fn icon_with_mime_type() {
        let icon = Icon::with_mime_type("https://example.com/icon.png", "image/png");
        assert!(icon.has_src());
        assert_eq!(icon.mime_type, Some("image/png".to_string()));
    }

    #[test]
    fn icon_full() {
        let icon = Icon::full("https://example.com/icon.png", "image/png", "32x32");
        assert_eq!(icon.src, Some("https://example.com/icon.png".to_string()));
        assert_eq!(icon.mime_type, Some("image/png".to_string()));
        assert_eq!(icon.sizes, Some("32x32".to_string()));
    }

    #[test]
    fn icon_data_uri() {
        let icon = Icon::new("data:image/png;base64,iVBORw0KGgo=");
        assert!(icon.is_data_uri());
    }

    #[test]
    fn icon_default_no_src() {
        let icon = Icon::default();
        assert!(!icon.has_src());
        assert!(!icon.is_data_uri());
    }

    #[test]
    fn icon_serialization() {
        let icon = Icon::full(
            "https://example.com/icon.svg",
            "image/svg+xml",
            "16x16 32x32",
        );
        let value = serde_json::to_value(&icon).expect("serialize");
        assert_eq!(value["src"], "https://example.com/icon.svg");
        assert_eq!(value["mimeType"], "image/svg+xml");
        assert_eq!(value["sizes"], "16x16 32x32");
    }

    #[test]
    fn icon_serialization_omits_none_fields() {
        let icon = Icon::new("https://example.com/icon.png");
        let value = serde_json::to_value(&icon).expect("serialize");
        assert!(value.get("src").is_some());
        assert!(value.get("mimeType").is_none());
        assert!(value.get("sizes").is_none());
    }

    #[test]
    fn icon_equality() {
        let a = Icon::new("https://example.com/icon.png");
        let b = Icon::new("https://example.com/icon.png");
        let c = Icon::new("https://example.com/other.png");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn legacy_icon_rejects_final_theme_without_mutating_accepted_wire() {
        let accepted = json!({
            "src": "https://example.com/icon.svg",
            "mimeType": "image/svg+xml",
            "sizes": "48x48"
        });
        let legacy: Icon = serde_json::from_value(accepted.clone()).expect("legacy icon");
        let baseline = accepted.clone();
        let mut planted = accepted.clone();
        planted["theme"] = json!("dark");
        assert!(
            serde_json::from_value::<Icon>(planted).is_err(),
            "the final-only theme field must not be silently discarded by the legacy icon"
        );
        assert_eq!(
            accepted, baseline,
            "the rejected one-field final addition cannot mutate accepted legacy wire state"
        );
        assert_eq!(serde_json::to_value(legacy).expect("legacy wire"), accepted);
    }

    // ========================================================================
    // Content Tests
    // ========================================================================

    #[test]
    fn content_text_serialization() {
        let content = Content::Text {
            text: "Hello, world!".to_string(),
        };
        let value = serde_json::to_value(&content).expect("serialize");
        assert_eq!(value["type"], "text");
        assert_eq!(value["text"], "Hello, world!");
    }

    #[test]
    fn content_image_serialization() {
        let content = Content::Image {
            data: "iVBORw0KGgo=".to_string(),
            mime_type: "image/png".to_string(),
        };
        let value = serde_json::to_value(&content).expect("serialize");
        assert_eq!(value["type"], "image");
        assert_eq!(value["data"], "iVBORw0KGgo=");
        assert_eq!(value["mimeType"], "image/png");
    }

    #[test]
    fn content_audio_serialization() {
        let content = Content::Audio {
            data: "UklGRg==".to_string(),
            mime_type: "audio/wav".to_string(),
        };
        let value = serde_json::to_value(&content).expect("serialize");
        assert_eq!(value["type"], "audio");
        assert_eq!(value["data"], "UklGRg==");
        assert_eq!(value["mimeType"], "audio/wav");
    }

    #[test]
    fn content_resource_serialization() {
        let content = Content::Resource {
            resource: ResourceContent {
                uri: "file://config.json".to_string(),
                mime_type: Some("application/json".to_string()),
                text: Some("{\"key\": \"value\"}".to_string()),
                blob: None,
            },
        };
        let value = serde_json::to_value(&content).expect("serialize");
        assert_eq!(value["type"], "resource");
        assert_eq!(value["resource"]["uri"], "file://config.json");
        assert_eq!(value["resource"]["mimeType"], "application/json");
        assert_eq!(value["resource"]["text"], "{\"key\": \"value\"}");
        assert!(value["resource"].get("blob").is_none());
    }

    #[test]
    fn content_text_deserialization() {
        let json = json!({"type": "text", "text": "Hello!"});
        let content: Content = serde_json::from_value(json).expect("deserialize");
        let text = match content {
            Content::Text { text } => Some(text),
            _ => None,
        };
        assert_eq!(text.as_deref(), Some("Hello!"));
    }

    #[test]
    fn content_image_deserialization() {
        let json = json!({"type": "image", "data": "abc123", "mimeType": "image/jpeg"});
        let content: Content = serde_json::from_value(json).expect("deserialize");
        let (data, mime_type) = match content {
            Content::Image { data, mime_type } => (Some(data), Some(mime_type)),
            _ => (None, None),
        };
        assert_eq!(data.as_deref(), Some("abc123"));
        assert_eq!(mime_type.as_deref(), Some("image/jpeg"));
    }

    #[test]
    fn content_audio_deserialization() {
        let json = json!({"type": "audio", "data": "abc123", "mimeType": "audio/mpeg"});
        let content: Content = serde_json::from_value(json).expect("deserialize");
        let (data, mime_type) = match content {
            Content::Audio { data, mime_type } => (Some(data), Some(mime_type)),
            _ => (None, None),
        };
        assert_eq!(data.as_deref(), Some("abc123"));
        assert_eq!(mime_type.as_deref(), Some("audio/mpeg"));
    }

    #[test]
    fn legacy_content_rejects_final_metadata_without_mutating_accepted_wire() {
        let accepted = json!({"type": "text", "text": "legacy text"});
        let legacy: Content = serde_json::from_value(accepted.clone()).expect("legacy content");
        let baseline = accepted.clone();
        let mut planted = accepted.clone();
        planted["_meta"] = json!({"com.example/renderHint": true});
        assert!(
            serde_json::from_value::<Content>(planted).is_err(),
            "the final-only content metadata must not be silently discarded by legacy content"
        );
        assert_eq!(
            accepted, baseline,
            "the rejected one-field final metadata addition cannot mutate accepted legacy wire state"
        );
        assert_eq!(serde_json::to_value(legacy).expect("legacy wire"), accepted);
    }

    // ========================================================================
    // ResourceContent Tests
    // ========================================================================

    #[test]
    fn resource_content_text_serialization() {
        let rc = ResourceContent {
            uri: "file://readme.md".to_string(),
            mime_type: Some("text/markdown".to_string()),
            text: Some("# Hello".to_string()),
            blob: None,
        };
        let value = serde_json::to_value(&rc).expect("serialize");
        assert_eq!(value["uri"], "file://readme.md");
        assert_eq!(value["mimeType"], "text/markdown");
        assert_eq!(value["text"], "# Hello");
        assert!(value.get("blob").is_none());
    }

    #[test]
    fn resource_content_blob_serialization() {
        let rc = ResourceContent {
            uri: "file://image.png".to_string(),
            mime_type: Some("image/png".to_string()),
            text: None,
            blob: Some("base64data".to_string()),
        };
        let value = serde_json::to_value(&rc).expect("serialize");
        assert_eq!(value["uri"], "file://image.png");
        assert!(value.get("text").is_none());
        assert_eq!(value["blob"], "base64data");
    }

    #[test]
    fn resource_content_minimal() {
        let rc = ResourceContent {
            uri: "file://test".to_string(),
            mime_type: None,
            text: None,
            blob: None,
        };
        let value = serde_json::to_value(&rc).expect("serialize");
        assert_eq!(value["uri"], "file://test");
        assert!(value.get("mimeType").is_none());
        assert!(value.get("text").is_none());
        assert!(value.get("blob").is_none());
    }

    // ========================================================================
    // Role Tests
    // ========================================================================

    #[test]
    fn role_serialization() {
        assert_eq!(serde_json::to_value(Role::User).unwrap(), "user");
        assert_eq!(serde_json::to_value(Role::Assistant).unwrap(), "assistant");
    }

    #[test]
    fn role_deserialization() {
        let user: Role = serde_json::from_value(json!("user")).expect("deserialize");
        assert_eq!(user, Role::User);
        let assistant: Role = serde_json::from_value(json!("assistant")).expect("deserialize");
        assert_eq!(assistant, Role::Assistant);
    }

    // ========================================================================
    // PromptMessage Tests
    // ========================================================================

    #[test]
    fn prompt_message_serialization() {
        let msg = PromptMessage {
            role: Role::User,
            content: Content::Text {
                text: "Tell me a joke".to_string(),
            },
        };
        let value = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(value["role"], "user");
        assert_eq!(value["content"]["type"], "text");
        assert_eq!(value["content"]["text"], "Tell me a joke");
    }

    #[test]
    fn prompt_message_assistant() {
        let msg = PromptMessage {
            role: Role::Assistant,
            content: Content::Text {
                text: "Here's a joke...".to_string(),
            },
        };
        let value = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(value["role"], "assistant");
    }

    // ========================================================================
    // PromptArgument Tests
    // ========================================================================

    #[test]
    fn prompt_argument_required() {
        let arg = PromptArgument {
            name: "language".to_string(),
            description: Some("Target language".to_string()),
            required: true,
        };
        let value = serde_json::to_value(&arg).expect("serialize");
        assert_eq!(value["name"], "language");
        assert_eq!(value["description"], "Target language");
        assert_eq!(value["required"], true);
    }

    #[test]
    fn prompt_argument_optional_omits_false() {
        let arg = PromptArgument {
            name: "style".to_string(),
            description: None,
            required: false,
        };
        let value = serde_json::to_value(&arg).expect("serialize");
        assert_eq!(value["name"], "style");
        assert!(value.get("description").is_none());
        // required=false should be omitted
        assert!(value.get("required").is_none());
    }

    #[test]
    fn prompt_argument_deserialization_defaults() {
        let json = json!({"name": "arg1"});
        let arg: PromptArgument = serde_json::from_value(json).expect("deserialize");
        assert_eq!(arg.name, "arg1");
        assert!(arg.description.is_none());
        assert!(!arg.required);
    }

    // ========================================================================
    // Tool Definition Tests
    // ========================================================================

    #[test]
    fn tool_minimal_serialization() {
        let tool = Tool {
            name: "add".to_string(),
            description: None,
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let value = serde_json::to_value(&tool).expect("serialize");
        assert_eq!(value["name"], "add");
        assert_eq!(value["inputSchema"]["type"], "object");
        assert!(value.get("description").is_none());
        assert!(value.get("outputSchema").is_none());
        assert!(value.get("icon").is_none());
        assert!(value.get("version").is_none());
        assert!(value.get("tags").is_none());
        assert!(value.get("annotations").is_none());
    }

    #[test]
    fn tool_full_serialization() {
        let tool = Tool {
            name: "compute".to_string(),
            description: Some("Runs a computation".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": { "x": { "type": "number" } },
                "required": ["x"]
            }),
            output_schema: Some(json!({"type": "number"})),
            icon: Some(Icon::new("https://example.com/icon.png")),
            version: Some("2.1.0".to_string()),
            tags: vec!["math".to_string(), "compute".to_string()],
            annotations: Some(ToolAnnotations::new().read_only(true).idempotent(true)),
        };
        let value = serde_json::to_value(&tool).expect("serialize");
        assert_eq!(value["name"], "compute");
        assert_eq!(value["description"], "Runs a computation");
        assert!(value["inputSchema"]["properties"]["x"].is_object());
        assert_eq!(value["outputSchema"]["type"], "number");
        assert_eq!(value["icon"]["src"], "https://example.com/icon.png");
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["tags"], json!(["math", "compute"]));
        assert_eq!(value["annotations"]["readOnlyHint"], true);
        assert_eq!(value["annotations"]["idempotentHint"], true);
    }

    #[test]
    fn tool_round_trip() {
        let json = json!({
            "name": "greet",
            "description": "Greets the user",
            "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
            "outputSchema": {"type": "string"},
            "version": "1.0.0",
            "tags": ["greeting"],
            "annotations": {"readOnlyHint": true}
        });
        let tool: Tool = serde_json::from_value(json.clone()).expect("deserialize");
        assert_eq!(tool.name, "greet");
        assert_eq!(tool.version, Some("1.0.0".to_string()));
        assert_eq!(tool.tags, vec!["greeting"]);
        assert!(tool.annotations.as_ref().unwrap().read_only.unwrap());
        let re_serialized = serde_json::to_value(&tool).expect("re-serialize");
        assert_eq!(re_serialized["name"], json["name"]);
    }

    // ========================================================================
    // Resource Definition Tests
    // ========================================================================

    #[test]
    fn resource_minimal_serialization() {
        let resource = Resource {
            uri: "file://test.txt".to_string(),
            name: "Test File".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let value = serde_json::to_value(&resource).expect("serialize");
        assert_eq!(value["uri"], "file://test.txt");
        assert_eq!(value["name"], "Test File");
        assert!(value.get("description").is_none());
        assert!(value.get("mimeType").is_none());
    }

    #[test]
    fn resource_full_round_trip() {
        let json = json!({
            "uri": "file://config.json",
            "name": "Config",
            "description": "Application configuration",
            "mimeType": "application/json",
            "version": "3.0.0",
            "tags": ["config", "json"]
        });
        let resource: Resource = serde_json::from_value(json).expect("deserialize");
        assert_eq!(resource.uri, "file://config.json");
        assert_eq!(resource.mime_type, Some("application/json".to_string()));
        assert_eq!(resource.tags, vec!["config", "json"]);
    }

    // ========================================================================
    // ResourceTemplate Tests
    // ========================================================================

    #[test]
    fn resource_template_serialization() {
        let template = ResourceTemplate {
            uri_template: "file://{path}".to_string(),
            name: "File Reader".to_string(),
            description: Some("Read any file".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
            version: None,
            tags: vec![],
        };
        let value = serde_json::to_value(&template).expect("serialize");
        assert_eq!(value["uriTemplate"], "file://{path}");
        assert_eq!(value["name"], "File Reader");
        assert_eq!(value["description"], "Read any file");
        assert_eq!(value["mimeType"], "text/plain");
    }

    // ========================================================================
    // Prompt Definition Tests
    // ========================================================================

    #[test]
    fn prompt_with_arguments() {
        let prompt = Prompt {
            name: "translate".to_string(),
            description: Some("Translate text".to_string()),
            arguments: vec![
                PromptArgument {
                    name: "text".to_string(),
                    description: Some("Text to translate".to_string()),
                    required: true,
                },
                PromptArgument {
                    name: "language".to_string(),
                    description: Some("Target language".to_string()),
                    required: true,
                },
                PromptArgument {
                    name: "style".to_string(),
                    description: None,
                    required: false,
                },
            ],
            icon: None,
            version: None,
            tags: vec![],
        };
        let value = serde_json::to_value(&prompt).expect("serialize");
        assert_eq!(value["name"], "translate");
        let args = value["arguments"].as_array().expect("arguments array");
        assert_eq!(args.len(), 3);
        assert_eq!(args[0]["name"], "text");
        assert_eq!(args[0]["required"], true);
        assert_eq!(args[2]["name"], "style");
        // required=false should be omitted
        assert!(args[2].get("required").is_none());
    }

    #[test]
    fn prompt_empty_arguments_omitted() {
        let prompt = Prompt {
            name: "simple".to_string(),
            description: None,
            arguments: vec![],
            icon: None,
            version: None,
            tags: vec![],
        };
        let value = serde_json::to_value(&prompt).expect("serialize");
        assert!(value.get("arguments").is_none());
    }

    // ========================================================================
    // TaskId Tests
    // ========================================================================

    #[test]
    fn task_id_new_has_prefix() {
        let id = TaskId::new();
        assert!(id.as_str().starts_with("task-"));
    }

    #[test]
    fn task_id_from_string() {
        let id = TaskId::from_string("task-abc123");
        assert_eq!(id.as_str(), "task-abc123");
    }

    #[test]
    fn task_id_display() {
        let id = TaskId::from_string("task-xyz");
        assert_eq!(format!("{id}"), "task-xyz");
    }

    #[test]
    fn task_id_from_impls() {
        let from_string: TaskId = "my-task".to_string().into();
        assert_eq!(from_string.as_str(), "my-task");

        let from_str: TaskId = "another-task".into();
        assert_eq!(from_str.as_str(), "another-task");
    }

    #[test]
    fn task_id_serialization() {
        let id = TaskId::from_string("task-1");
        let value = serde_json::to_value(&id).expect("serialize");
        assert_eq!(value, "task-1");

        let deserialized: TaskId = serde_json::from_value(json!("task-2")).expect("deserialize");
        assert_eq!(deserialized.as_str(), "task-2");
    }

    #[test]
    fn task_id_equality() {
        let a = TaskId::from_string("task-1");
        let b = TaskId::from_string("task-1");
        let c = TaskId::from_string("task-2");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ========================================================================
    // TaskStatus Tests
    // ========================================================================

    #[test]
    fn task_status_is_terminal() {
        assert!(TaskStatus::Completed.is_terminal());
        assert!(TaskStatus::Failed.is_terminal());
        assert!(TaskStatus::Cancelled.is_terminal());
        assert!(!TaskStatus::Pending.is_terminal());
        assert!(!TaskStatus::Running.is_terminal());
    }

    #[test]
    fn task_status_is_active() {
        assert!(TaskStatus::Pending.is_active());
        assert!(TaskStatus::Running.is_active());
        assert!(!TaskStatus::Completed.is_active());
        assert!(!TaskStatus::Failed.is_active());
        assert!(!TaskStatus::Cancelled.is_active());
    }

    #[test]
    fn task_status_serialization() {
        assert_eq!(
            serde_json::to_value(TaskStatus::Pending).unwrap(),
            "pending"
        );
        assert_eq!(
            serde_json::to_value(TaskStatus::Running).unwrap(),
            "running"
        );
        assert_eq!(
            serde_json::to_value(TaskStatus::Completed).unwrap(),
            "completed"
        );
        assert_eq!(serde_json::to_value(TaskStatus::Failed).unwrap(), "failed");
        assert_eq!(
            serde_json::to_value(TaskStatus::Cancelled).unwrap(),
            "cancelled"
        );
    }

    #[test]
    fn task_status_deserialization() {
        assert_eq!(
            serde_json::from_value::<TaskStatus>(json!("pending")).unwrap(),
            TaskStatus::Pending
        );
        assert_eq!(
            serde_json::from_value::<TaskStatus>(json!("running")).unwrap(),
            TaskStatus::Running
        );
        assert_eq!(
            serde_json::from_value::<TaskStatus>(json!("completed")).unwrap(),
            TaskStatus::Completed
        );
        assert_eq!(
            serde_json::from_value::<TaskStatus>(json!("failed")).unwrap(),
            TaskStatus::Failed
        );
        assert_eq!(
            serde_json::from_value::<TaskStatus>(json!("cancelled")).unwrap(),
            TaskStatus::Cancelled
        );
    }

    // ========================================================================
    // TaskInfo Tests
    // ========================================================================

    #[test]
    fn task_info_serialization() {
        let info = TaskInfo {
            id: TaskId::from_string("task-1"),
            task_type: "compute".to_string(),
            status: TaskStatus::Running,
            progress: Some(0.5),
            message: Some("Processing...".to_string()),
            created_at: "2026-01-28T00:00:00Z".to_string(),
            started_at: Some("2026-01-28T00:01:00Z".to_string()),
            completed_at: None,
            error: None,
        };
        let value = serde_json::to_value(&info).expect("serialize");
        assert_eq!(value["id"], "task-1");
        assert_eq!(value["taskType"], "compute");
        assert_eq!(value["status"], "running");
        assert_eq!(value["progress"], 0.5);
        assert_eq!(value["message"], "Processing...");
        assert_eq!(value["createdAt"], "2026-01-28T00:00:00Z");
        assert_eq!(value["startedAt"], "2026-01-28T00:01:00Z");
        assert!(value.get("completedAt").is_none());
        assert!(value.get("error").is_none());
    }

    #[test]
    fn task_info_minimal() {
        let json = json!({
            "id": "task-2",
            "taskType": "demo",
            "status": "pending",
            "createdAt": "2026-01-28T00:00:00Z"
        });
        let info: TaskInfo = serde_json::from_value(json).expect("deserialize");
        assert_eq!(info.id.as_str(), "task-2");
        assert_eq!(info.status, TaskStatus::Pending);
        assert!(info.progress.is_none());
        assert!(info.message.is_none());
    }

    // ========================================================================
    // TaskResult Tests
    // ========================================================================

    #[test]
    fn task_result_success() {
        let result = TaskResult {
            id: TaskId::from_string("task-1"),
            success: true,
            data: Some(json!({"value": 42})),
            error: None,
        };
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["id"], "task-1");
        assert_eq!(value["success"], true);
        assert_eq!(value["data"]["value"], 42);
        assert!(value.get("error").is_none());
    }

    #[test]
    fn task_result_failure() {
        let result = TaskResult {
            id: TaskId::from_string("task-2"),
            success: false,
            data: None,
            error: Some("computation failed".to_string()),
        };
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["success"], false);
        assert!(value.get("data").is_none());
        assert_eq!(value["error"], "computation failed");
    }

    // ========================================================================
    // SamplingContent Tests
    // ========================================================================

    #[test]
    fn sampling_content_text_serialization() {
        let content = SamplingContent::Text {
            text: "Hello".to_string(),
        };
        let value = serde_json::to_value(&content).expect("serialize");
        assert_eq!(value["type"], "text");
        assert_eq!(value["text"], "Hello");
    }

    #[test]
    fn sampling_content_image_serialization() {
        let content = SamplingContent::Image {
            data: "base64data".to_string(),
            mime_type: "image/png".to_string(),
        };
        let value = serde_json::to_value(&content).expect("serialize");
        assert_eq!(value["type"], "image");
        assert_eq!(value["data"], "base64data");
        assert_eq!(value["mimeType"], "image/png");
    }

    // ========================================================================
    // SamplingMessage Tests
    // ========================================================================

    #[test]
    fn sampling_message_user_constructor() {
        let msg = SamplingMessage::user("Hello!");
        let value = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(value["role"], "user");
        assert_eq!(value["content"]["type"], "text");
        assert_eq!(value["content"]["text"], "Hello!");
    }

    #[test]
    fn sampling_message_assistant_constructor() {
        let msg = SamplingMessage::assistant("Hi there!");
        let value = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(value["role"], "assistant");
        assert_eq!(value["content"]["text"], "Hi there!");
    }

    // ========================================================================
    // ModelPreferences Tests
    // ========================================================================

    #[test]
    fn model_preferences_default() {
        let prefs = ModelPreferences::default();
        let value = serde_json::to_value(&prefs).expect("serialize");
        // All optional fields should be omitted
        assert!(value.get("hints").is_none());
        assert!(value.get("costPriority").is_none());
        assert!(value.get("speedPriority").is_none());
        assert!(value.get("intelligencePriority").is_none());
    }

    #[test]
    fn model_preferences_full() {
        let prefs = ModelPreferences {
            hints: vec![ModelHint {
                name: Some("claude-3".to_string()),
            }],
            cost_priority: Some(0.3),
            speed_priority: Some(0.5),
            intelligence_priority: Some(0.9),
        };
        let value = serde_json::to_value(&prefs).expect("serialize");
        assert_eq!(value["hints"][0]["name"], "claude-3");
        assert_eq!(value["costPriority"], 0.3);
        assert_eq!(value["speedPriority"], 0.5);
        assert_eq!(value["intelligencePriority"], 0.9);
    }

    // ========================================================================
    // StopReason Tests
    // ========================================================================

    #[test]
    fn stop_reason_serialization() {
        assert_eq!(
            serde_json::to_value(StopReason::EndTurn).unwrap(),
            "endTurn"
        );
        assert_eq!(
            serde_json::to_value(StopReason::StopSequence).unwrap(),
            "stopSequence"
        );
        assert_eq!(
            serde_json::to_value(StopReason::MaxTokens).unwrap(),
            "maxTokens"
        );
    }

    #[test]
    fn stop_reason_deserialization() {
        assert_eq!(
            serde_json::from_value::<StopReason>(json!("endTurn")).unwrap(),
            StopReason::EndTurn
        );
        assert_eq!(
            serde_json::from_value::<StopReason>(json!("stopSequence")).unwrap(),
            StopReason::StopSequence
        );
        assert_eq!(
            serde_json::from_value::<StopReason>(json!("maxTokens")).unwrap(),
            StopReason::MaxTokens
        );
    }

    #[test]
    fn stop_reason_default() {
        assert_eq!(StopReason::default(), StopReason::EndTurn);
    }

    // ========================================================================
    // PROTOCOL_VERSION Test
    // ========================================================================

    #[test]
    fn protocol_version_value() {
        assert_eq!(PROTOCOL_VERSION, "2024-11-05");
    }

    // ========================================================================
    // ToolAnnotations Tests
    // ========================================================================

    #[test]
    fn tool_annotations_default_is_empty() {
        let ann = ToolAnnotations::new();
        assert!(ann.is_empty());
    }

    #[test]
    fn tool_annotations_builder_chain() {
        let ann = ToolAnnotations::new()
            .read_only(true)
            .idempotent(true)
            .destructive(false)
            .open_world_hint(false);

        assert_eq!(ann.read_only, Some(true));
        assert_eq!(ann.idempotent, Some(true));
        assert_eq!(ann.destructive, Some(false));
        assert_eq!(ann.open_world_hint, Some(false));
        assert!(!ann.is_empty());
    }

    #[test]
    fn tool_annotations_single_field_not_empty() {
        assert!(!ToolAnnotations::new().destructive(true).is_empty());
        assert!(!ToolAnnotations::new().idempotent(false).is_empty());
        assert!(!ToolAnnotations::new().read_only(true).is_empty());
        assert!(!ToolAnnotations::new().open_world_hint(true).is_empty());
    }

    #[test]
    fn tool_annotations_serialization_skips_none() {
        let ann = ToolAnnotations::new().read_only(true);
        let value = serde_json::to_value(&ann).expect("serialize");
        assert_eq!(value["readOnlyHint"], true);
        assert!(value.get("destructiveHint").is_none());
        assert!(value.get("idempotentHint").is_none());
        assert!(value.get("openWorldHint").is_none());
    }

    #[test]
    fn tool_annotations_round_trip() {
        let ann = ToolAnnotations::new()
            .destructive(true)
            .idempotent(false)
            .open_world_hint(true);
        let json_str = serde_json::to_string(&ann).expect("serialize");
        let deserialized: ToolAnnotations = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(ann, deserialized);
    }

    // ========================================================================
    // Icon Tests
    // ========================================================================

    #[test]
    fn icon_is_data_uri_with_data_prefix() {
        let icon = Icon {
            src: Some("data:image/png;base64,iVBOR".to_string()),
            mime_type: None,
            sizes: None,
        };
        assert!(icon.is_data_uri());
    }

    #[test]
    fn icon_is_data_uri_without_data_prefix() {
        let icon = Icon {
            src: Some("https://example.com/icon.png".to_string()),
            mime_type: None,
            sizes: None,
        };
        assert!(!icon.is_data_uri());
    }

    #[test]
    fn icon_is_data_uri_no_src() {
        let icon = Icon {
            src: None,
            mime_type: None,
            sizes: None,
        };
        assert!(!icon.is_data_uri());
    }

    #[test]
    fn icon_is_data_uri_empty_string() {
        let icon = Icon {
            src: Some(String::new()),
            mime_type: None,
            sizes: None,
        };
        assert!(!icon.is_data_uri());
    }

    // ========================================================================
    // Content Binary Factory Tests
    // ========================================================================

    #[test]
    fn content_image_bytes_encodes_base64() {
        let bytes: &[u8] = &[0x89, 0x50, 0x4E, 0x47]; // PNG header
        let content = Content::image_bytes(bytes, "image/png");
        match &content {
            Content::Image { data, mime_type } => {
                assert_eq!(mime_type, "image/png");
                // Verify it's valid base64 that decodes back
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .expect("valid base64");
                assert_eq!(decoded, bytes);
            }
            _ => panic!("expected Image content"),
        }
    }

    #[test]
    fn content_image_bytes_empty() {
        let content = Content::image_bytes(&[] as &[u8], "image/png");
        match &content {
            Content::Image { data, .. } => {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .expect("valid base64");
                assert!(decoded.is_empty());
            }
            _ => panic!("expected Image content"),
        }
    }

    #[test]
    fn content_audio_bytes_encodes_base64() {
        let bytes: &[u8] = &[0x52, 0x49, 0x46, 0x46]; // RIFF header
        let content = Content::audio_bytes(bytes, "audio/wav");
        match &content {
            Content::Audio { data, mime_type } => {
                assert_eq!(mime_type, "audio/wav");
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .expect("valid base64");
                assert_eq!(decoded, bytes);
            }
            _ => panic!("expected Audio content"),
        }
    }

    #[test]
    fn content_resource_blob_bytes_encodes_base64() {
        let bytes: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let content = Content::resource_blob_bytes(
            "blob://test",
            Some("application/octet-stream".into()),
            bytes,
        );
        match &content {
            Content::Resource {
                resource: ResourceContent { uri, blob, .. },
            } => {
                assert_eq!(uri, "blob://test");
                let blob_data = blob.as_ref().expect("should have blob");
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(blob_data)
                    .expect("valid base64");
                assert_eq!(decoded, bytes);
            }
            _ => panic!("expected Resource content"),
        }
    }

    #[test]
    fn content_resource_blob_bytes_none_mime() {
        let content = Content::resource_blob_bytes("blob://test", None, &[1, 2, 3]);
        match &content {
            Content::Resource {
                resource: ResourceContent { mime_type, .. },
            } => {
                assert!(mime_type.is_none());
            }
            _ => panic!("expected Resource content"),
        }
    }

    // =========================================================================
    // Additional coverage tests (bd-1cd5)
    // =========================================================================

    #[test]
    fn root_new_constructor() {
        let root = Root::new("file:///home/user/project");
        assert_eq!(root.uri, "file:///home/user/project");
        assert!(root.name.is_none());
    }

    #[test]
    fn root_new_from_string() {
        let uri = String::from("file:///tmp");
        let root = Root::new(uri);
        assert_eq!(root.uri, "file:///tmp");
    }

    #[test]
    fn root_with_name_constructor() {
        let root = Root::with_name("file:///workspace", "My Project");
        assert_eq!(root.uri, "file:///workspace");
        assert_eq!(root.name.as_deref(), Some("My Project"));
    }

    #[test]
    fn root_with_name_from_strings() {
        let uri = String::from("file:///src");
        let name = String::from("Source");
        let root = Root::with_name(uri, name);
        assert_eq!(root.uri, "file:///src");
        assert_eq!(root.name.unwrap(), "Source");
    }

    #[test]
    fn content_text_constructor() {
        let content = Content::text("hello world");
        match &content {
            Content::Text { text } => assert_eq!(text, "hello world"),
            _ => panic!("expected Text content"),
        }
    }

    #[test]
    fn content_text_from_string() {
        let s = String::from("owned string");
        let content = Content::text(s);
        match &content {
            Content::Text { text } => assert_eq!(text, "owned string"),
            _ => panic!("expected Text content"),
        }
    }

    #[test]
    fn content_image_base64_constructor() {
        let content = Content::image_base64("aGVsbG8=", "image/png");
        match &content {
            Content::Image { data, mime_type } => {
                assert_eq!(data, "aGVsbG8=");
                assert_eq!(mime_type, "image/png");
            }
            _ => panic!("expected Image content"),
        }
    }

    #[test]
    fn content_audio_base64_constructor() {
        let content = Content::audio_base64("AAAA", "audio/mp3");
        match &content {
            Content::Audio { data, mime_type } => {
                assert_eq!(data, "AAAA");
                assert_eq!(mime_type, "audio/mp3");
            }
            _ => panic!("expected Audio content"),
        }
    }

    #[test]
    fn content_resource_text_constructor() {
        let content = Content::resource_text(
            "file:///readme.md",
            Some("text/markdown".to_string()),
            "# Hello",
        );
        match &content {
            Content::Resource { resource } => {
                assert_eq!(resource.uri, "file:///readme.md");
                assert_eq!(resource.mime_type.as_deref(), Some("text/markdown"));
                assert_eq!(resource.text.as_deref(), Some("# Hello"));
                assert!(resource.blob.is_none());
            }
            _ => panic!("expected Resource content"),
        }
    }

    #[test]
    fn content_resource_text_no_mime() {
        let content = Content::resource_text("file:///data.txt", None, "data");
        match &content {
            Content::Resource { resource } => {
                assert!(resource.mime_type.is_none());
                assert_eq!(resource.text.as_deref(), Some("data"));
            }
            _ => panic!("expected Resource content"),
        }
    }

    #[test]
    fn content_resource_blob_base64_constructor() {
        let content = Content::resource_blob_base64(
            "file:///image.png",
            Some("image/png".to_string()),
            "iVBOR",
        );
        match &content {
            Content::Resource { resource } => {
                assert_eq!(resource.uri, "file:///image.png");
                assert_eq!(resource.mime_type.as_deref(), Some("image/png"));
                assert!(resource.text.is_none());
                assert_eq!(resource.blob.as_deref(), Some("iVBOR"));
            }
            _ => panic!("expected Resource content"),
        }
    }

    #[test]
    fn content_resource_blob_base64_no_mime() {
        let content = Content::resource_blob_base64("file:///bin", None, "AQID");
        match &content {
            Content::Resource { resource } => {
                assert!(resource.mime_type.is_none());
                assert_eq!(resource.blob.as_deref(), Some("AQID"));
            }
            _ => panic!("expected Resource content"),
        }
    }

    #[test]
    fn final_models_and_sampling_blocks_round_trip_without_legacy_fields() {
        let tool_wire = json!({
            "name": "weather",
            "title": "Weather lookup",
            "description": "Looks up forecast data",
            "icons": [{"src": "https://example.test/weather.png"}],
            "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}},
            "annotations": {"title": "Forecast", "readOnlyHint": true},
            "_meta": {"com.example/source": "catalog"}
        });
        let tool: FinalTool = serde_json::from_value(tool_wire.clone())
            .expect("final tool accepts final metadata and icons array");
        assert_eq!(tool.title.as_deref(), Some("Weather lookup"));
        assert_eq!(
            serde_json::to_value(&tool).expect("final tool re-encodes"),
            tool_wire
        );

        let sampling_wire = json!({
            "role": "assistant",
            "content": [
                {"type": "tool_use", "id": "call-1", "name": "weather", "input": {"city": "Boston"}},
                {"type": "tool_result", "toolUseId": "call-1", "content": [{"type": "text", "text": "sunny"}], "structuredContent": {"temperature": 22}}
            ],
            "_meta": {"com.example/turn": 4}
        });
        let message: FinalSamplingMessage = serde_json::from_value(sampling_wire.clone())
            .expect("final sampling admits tool-use and tool-result blocks");
        assert_eq!(
            serde_json::to_value(message).expect("final sampling re-encodes"),
            sampling_wire
        );
    }

    #[test]
    fn final_tool_rejects_one_legacy_icon_field_without_mutating_final_baseline() {
        let accepted = json!({
            "name": "weather",
            "inputSchema": {"type": "object"}
        });
        let baseline: FinalTool =
            serde_json::from_value(accepted.clone()).expect("final tool baseline");
        let mut planted = accepted.clone();
        planted["icon"] = json!({"src": "https://example.test/legacy.png"});
        assert!(
            serde_json::from_value::<FinalTool>(planted).is_err(),
            "only the legacy singular icon field changes the final model"
        );
        assert_eq!(
            serde_json::to_value(baseline).expect("baseline re-encodes"),
            accepted,
            "legacy-field rejection does not mutate final model state"
        );
    }

    #[test]
    fn final_tool_output_schema_distinguishes_absence_from_explicit_null() {
        let absent_wire = json!({
            "name": "weather",
            "inputSchema": {"type": "object"}
        });
        let absent: FinalTool =
            serde_json::from_value(absent_wire.clone()).expect("absent outputSchema is valid");
        assert!(absent.output_schema.is_none());
        assert_eq!(
            serde_json::to_value(absent).expect("absent outputSchema re-encodes"),
            absent_wire
        );

        let accepted_wire = json!({
            "name": "weather",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "null"}
        });
        let accepted: FinalTool = serde_json::from_value(accepted_wire.clone())
            .expect("an object schema whose admitted instances are null is valid");

        let mut planted = accepted_wire.clone();
        planted["outputSchema"] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<FinalTool>(planted).is_err(),
            "a present outputSchema must itself be an object, not JSON null"
        );
        assert_eq!(
            serde_json::to_value(accepted).expect("accepted outputSchema re-encodes"),
            accepted_wire,
            "rejecting the one-field null plant cannot mutate the accepted model"
        );
    }
}
