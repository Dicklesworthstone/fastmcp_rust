//! MCP protocol types.
//!
//! Core types used in MCP communication.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::common_types::{
    AbsoluteUri, Annotations, ContentBlock, EmbeddedResourceContents, Implementation, JsonInteger,
    OpenMetadata, RawIcon, SamplingContentBlock,
};
use crate::extensions::MCP_APPS_HTML_MIME_TYPE;
use crate::messages::{FinalCallToolResult, FinalCoreResult, FinalReadResourceResult};
use crate::result::{MAX_RESULT_CONTAINER_MEMBERS, MAX_RESULT_ENCODED_BYTES};
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
    /// Argument-completion capability (`completion/complete`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completions: Option<CompletionsCapability>,
    /// Background tasks capability (Docket/SEP-1686).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tasks: Option<TasksCapability>,
    /// Experimental, non-standard capabilities that the server supports.
    ///
    /// Schema: `type: object`, `additionalProperties: JSONObject`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<BTreeMap<String, serde_json::Value>>,
    /// Optional MCP extensions that the server supports.
    ///
    /// Keys are extension identifiers and values are per-extension settings
    /// objects; an empty object indicates support with no settings. Schema:
    /// `type: object`, `additionalProperties: JSONObject`.
    ///
    /// `serde_json::Value` rather than a nested map, symmetrical with
    /// `ClientCapabilities`: `additionalProperties` is UNSET on this type in
    /// the schema, i.e. open, so it must not gain `deny_unknown_fields`, and a
    /// non-object value must stay representable so consumers reject it at a
    /// typed boundary instead of failing the whole deserialization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<BTreeMap<String, serde_json::Value>>,
}

/// Empty object advertised when `completion/complete` is installed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompletionsCapability {}

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
    /// Experimental, non-standard capabilities that the client supports.
    ///
    /// Schema: `type: object`, `additionalProperties: JSONObject`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<BTreeMap<String, serde_json::Value>>,
    /// Optional MCP extensions that the client supports.
    ///
    /// Keys are extension identifiers (for example
    /// `io.modelcontextprotocol/oauth-client-credentials`) and values are
    /// per-extension settings objects; an empty object indicates support with
    /// no settings. Schema: `type: object`, `additionalProperties: JSONObject`.
    ///
    /// The value type is deliberately `serde_json::Value` rather than a nested
    /// map, matching `ServerDiscoverCapabilities::members` and the `additional`
    /// fields in this file. `ClientCapabilities` has `additionalProperties`
    /// UNSET in the schema, i.e. open, so this must not gain
    /// `deny_unknown_fields`, and a non-object value must stay representable so
    /// consumers can reject it at a typed boundary instead of failing the whole
    /// deserialization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<BTreeMap<String, serde_json::Value>>,
}

/// Sampling capability.
///
/// MCP 2026-07-28 lets a client declare two optional sub-capabilities,
/// `context` (supports `includeContext`) and `tools` (supports `tools` /
/// `toolChoice`). Both are retained so a decoded capability re-encodes without
/// silently dropping what the peer declared.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SamplingCapability {
    /// Present if the client supports context inclusion via `includeContext`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Map<String, serde_json::Value>>,
    /// Present if the client supports tool use via `tools` and `toolChoice`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<serde_json::Map<String, serde_json::Value>>,
}

impl SamplingCapability {
    /// Declares sampling with tool-use support (`sampling.tools`).
    #[must_use]
    pub fn with_tools(mut self) -> Self {
        self.tools = Some(serde_json::Map::new());
        self
    }

    /// Declares sampling with context-inclusion support (`sampling.context`).
    #[must_use]
    pub fn with_context(mut self) -> Self {
        self.context = Some(serde_json::Map::new());
        self
    }
}

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
    /// Absence differs from an empty name; an explicit null is not a name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_root_name"
    )]
    pub name: Option<String>,
}

fn deserialize_optional_root_name<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
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

impl ClientInfo {
    /// Projects this exact-2024 name/version pair into a final Implementation.
    ///
    /// Empty name or version is replaced with a nonempty fallback so modern
    /// request `_meta` can always carry a typed identity object.
    #[must_use]
    pub fn to_implementation(&self) -> Implementation {
        let name = if self.name.is_empty() {
            "unknown"
        } else {
            self.name.as_str()
        };
        let version = if self.version.is_empty() {
            "0"
        } else {
            self.version.as_str()
        };
        Implementation::try_new(name, version).expect("the fallback client identity is nonempty")
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(
        rename = "uriTemplate",
        serialize_with = "serialize_resource_uri_template",
        deserialize_with = "deserialize_resource_uri_template"
    )]
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

fn deserialize_resource_uri_template<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    crate::UriTemplate::parse(&value)
        .map(|_| value)
        .map_err(D::Error::custom)
}

fn serialize_resource_uri_template<S>(value: &String, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    crate::UriTemplate::parse(value).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(value)
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

// ============================================================================
// MCP Apps metadata, lifecycle, and result projection
// ============================================================================

/// Nested `_meta` member reserved by the MCP Apps protocol.
pub const MCP_APPS_UI_METADATA_KEY: &str = "ui";
/// Deprecated flat metadata member that this final-only surface rejects.
pub const MCP_APPS_DEPRECATED_RESOURCE_URI_METADATA_KEY: &str = "ui/resourceUri";
/// Maximum members in a closed nested MCP Apps tool `ui` metadata object.
pub const MAX_MCP_APPS_UI_METADATA_MEMBERS: usize = 2;
/// Maximum audience entries retained by one Apps tool visibility declaration.
pub const MAX_MCP_APPS_TOOL_VISIBILITY_ENTRIES: usize = 128;
/// Maximum origins retained by one Apps CSP directive.
pub const MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE: usize = 128;
/// Maximum UTF-8 bytes retained for one Apps CSP origin or host-selected domain.
pub const MAX_MCP_APPS_CSP_DOMAIN_BYTES: usize = 2_048;

/// A tool audience declared in nested MCP Apps metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum McpAppsToolVisibility {
    /// The model can discover and invoke the tool.
    Model,
    /// The rendered App can invoke the tool through its later bridge runtime.
    App,
}

/// A Host-selected way to present an App View.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum McpAppsDisplayMode {
    /// The View appears in normal document flow.
    Inline,
    /// The View occupies the host's full display surface.
    Fullscreen,
    /// The View is presented picture-in-picture.
    Pip,
}

/// Closed Apps metadata attached to a final `Tool` under `_meta.ui`.
///
/// The resource URI is intentionally typed as an exact authority-form
/// `ui://` URI. Security configuration belongs to resource metadata and is
/// intentionally not part of this non-security protocol slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpAppsToolMetadata {
    /// UI resource rendered when this tool is invoked, when declared.
    pub resource_uri: Option<AbsoluteUri>,
    /// Optional explicit audiences; absence retains the Apps default of both.
    pub visibility: Option<Vec<McpAppsToolVisibility>>,
}

impl McpAppsToolMetadata {
    /// Creates validated closed Apps tool metadata.
    pub fn try_new(
        resource_uri: Option<AbsoluteUri>,
        visibility: Option<Vec<McpAppsToolVisibility>>,
    ) -> Result<Self, McpAppsMetadataError> {
        if resource_uri
            .as_ref()
            .is_some_and(|resource_uri| !resource_uri.as_str().starts_with("ui://"))
        {
            return Err(McpAppsMetadataError::ResourceUriMustUseUiPrefix);
        }
        if visibility
            .as_ref()
            .is_some_and(|visibility| visibility.len() > MAX_MCP_APPS_TOOL_VISIBILITY_ENTRIES)
        {
            return Err(McpAppsMetadataError::TooManyToolVisibilityEntries);
        }
        Ok(Self {
            resource_uri,
            visibility,
        })
    }

    /// Returns the effective visibility without changing absent versus present
    /// wire state.
    #[must_use]
    pub fn effective_visibility(&self) -> &[McpAppsToolVisibility] {
        const DEFAULT_VISIBILITY: [McpAppsToolVisibility; 2] =
            [McpAppsToolVisibility::Model, McpAppsToolVisibility::App];
        self.visibility.as_deref().unwrap_or(&DEFAULT_VISIBILITY)
    }

    /// Produces a standalone final `_meta` object containing this exact nested
    /// Apps member.
    pub fn to_open_metadata(&self) -> Result<OpenMetadata, McpAppsMetadataError> {
        let value =
            serde_json::to_value(self).map_err(|_| McpAppsMetadataError::InvalidToolMetadata)?;
        OpenMetadata::try_from_entries([(MCP_APPS_UI_METADATA_KEY.to_owned(), value)])
            .map_err(|_| McpAppsMetadataError::InvalidToolMetadata)
    }

    /// Merges this typed `ui` member into existing final open metadata.
    pub fn merge_into(
        &self,
        metadata: &OpenMetadata,
    ) -> Result<OpenMetadata, McpAppsMetadataError> {
        reject_deprecated_mcp_apps_metadata(metadata)?;
        if metadata.entries().contains_key(MCP_APPS_UI_METADATA_KEY) {
            return Err(McpAppsMetadataError::UiMetadataAlreadyPresent);
        }
        let mut entries = metadata.entries().clone();
        entries.insert(
            MCP_APPS_UI_METADATA_KEY.to_owned(),
            serde_json::to_value(self).map_err(|_| McpAppsMetadataError::InvalidToolMetadata)?,
        );
        OpenMetadata::try_from_entries(entries)
            .map_err(|_| McpAppsMetadataError::InvalidToolMetadata)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct McpAppsToolMetadataWire {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_mcp_apps_field"
    )]
    resource_uri: Option<AbsoluteUri>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_mcp_apps_field"
    )]
    visibility: Option<Vec<McpAppsToolVisibility>>,
}

// Apps fields may be omitted, but their schemas never admit explicit null.
// `default` handles absence; deserializing T itself handles a present member
// without Option's otherwise silent conversion of null into absence.
fn deserialize_present_mcp_apps_field<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

// A derived struct visitor also accepts positional sequences. Apps metadata
// requires objects, especially for empty permission markers: `[]` must never
// become `{}`. Keep decoding on the map stream so each closed wire struct's
// unknown-field and duplicate-field checks bound its member traversal.
fn deserialize_mcp_apps_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ObjectVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an MCP Apps metadata object")
        }

        fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(ObjectVisitor::<T>(std::marker::PhantomData))
}

impl Serialize for McpAppsToolMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Self::try_new(self.resource_uri.clone(), self.visibility.clone())
            .map_err(serde::ser::Error::custom)?;
        McpAppsToolMetadataWire {
            resource_uri: self.resource_uri.clone(),
            visibility: self.visibility.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for McpAppsToolMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire: McpAppsToolMetadataWire = deserialize_mcp_apps_object(deserializer)?;
        Self::try_new(wire.resource_uri, wire.visibility).map_err(serde::de::Error::custom)
    }
}

/// Bounded CSP origins declared by an Apps resource.
///
/// These declarations remain requests to the host. They do not authorize a
/// network connection, nested frame, or base URI without host-side policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct McpAppsResourceCsp {
    /// Origins for network requests (`connect-src`).
    pub connect_domains: Option<Vec<String>>,
    /// Origins for static resources (`img-src`, `script-src`, and related directives).
    pub resource_domains: Option<Vec<String>>,
    /// Origins allowed for nested frames (`frame-src`).
    pub frame_domains: Option<Vec<String>>,
    /// Origins allowed as document base URIs (`base-uri`).
    pub base_uri_domains: Option<Vec<String>>,
}

impl McpAppsResourceCsp {
    /// Creates a bounded CSP declaration without granting any host authority.
    pub fn try_new(
        connect_domains: Option<Vec<String>>,
        resource_domains: Option<Vec<String>>,
        frame_domains: Option<Vec<String>>,
        base_uri_domains: Option<Vec<String>>,
    ) -> Result<Self, McpAppsMetadataError> {
        for domains in [
            connect_domains.as_deref(),
            resource_domains.as_deref(),
            frame_domains.as_deref(),
            base_uri_domains.as_deref(),
        ] {
            validate_mcp_apps_domains(domains)?;
        }
        Ok(Self {
            connect_domains,
            resource_domains,
            frame_domains,
            base_uri_domains,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct McpAppsResourceCspWire {
    #[serde(
        rename = "connectDomains",
        default,
        deserialize_with = "deserialize_present_mcp_apps_field",
        skip_serializing_if = "Option::is_none"
    )]
    connect: Option<Vec<String>>,
    #[serde(
        rename = "resourceDomains",
        default,
        deserialize_with = "deserialize_present_mcp_apps_field",
        skip_serializing_if = "Option::is_none"
    )]
    resources: Option<Vec<String>>,
    #[serde(
        rename = "frameDomains",
        default,
        deserialize_with = "deserialize_present_mcp_apps_field",
        skip_serializing_if = "Option::is_none"
    )]
    frames: Option<Vec<String>>,
    #[serde(
        rename = "baseUriDomains",
        default,
        deserialize_with = "deserialize_present_mcp_apps_field",
        skip_serializing_if = "Option::is_none"
    )]
    base_uris: Option<Vec<String>>,
}

impl Serialize for McpAppsResourceCsp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Self::try_new(
            self.connect_domains.clone(),
            self.resource_domains.clone(),
            self.frame_domains.clone(),
            self.base_uri_domains.clone(),
        )
        .map_err(serde::ser::Error::custom)?;
        McpAppsResourceCspWire {
            connect: self.connect_domains.clone(),
            resources: self.resource_domains.clone(),
            frames: self.frame_domains.clone(),
            base_uris: self.base_uri_domains.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for McpAppsResourceCsp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire: McpAppsResourceCspWire = deserialize_mcp_apps_object(deserializer)?;
        Self::try_new(wire.connect, wire.resources, wire.frames, wire.base_uris)
            .map_err(serde::de::Error::custom)
    }
}

/// An empty-object Apps sandbox permission marker.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct McpAppsResourcePermission {}

impl<'de> Deserialize<'de> for McpAppsResourcePermission {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PermissionMarker {}

        let _: PermissionMarker = deserialize_mcp_apps_object(deserializer)?;
        Ok(Self {})
    }
}

/// Optional sandbox permissions requested by an Apps resource.
///
/// Presence requests a host permission; absence does not. A host may further
/// restrict or reject every requested permission.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAppsResourcePermissions {
    /// Camera permission marker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub camera: Option<McpAppsResourcePermission>,
    /// Microphone permission marker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub microphone: Option<McpAppsResourcePermission>,
    /// Geolocation permission marker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geolocation: Option<McpAppsResourcePermission>,
    /// Clipboard-write permission marker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clipboard_write: Option<McpAppsResourcePermission>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct McpAppsResourcePermissionsWire {
    #[serde(default, deserialize_with = "deserialize_present_mcp_apps_field")]
    camera: Option<McpAppsResourcePermission>,
    #[serde(default, deserialize_with = "deserialize_present_mcp_apps_field")]
    microphone: Option<McpAppsResourcePermission>,
    #[serde(default, deserialize_with = "deserialize_present_mcp_apps_field")]
    geolocation: Option<McpAppsResourcePermission>,
    #[serde(default, deserialize_with = "deserialize_present_mcp_apps_field")]
    clipboard_write: Option<McpAppsResourcePermission>,
}

impl<'de> Deserialize<'de> for McpAppsResourcePermissions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire: McpAppsResourcePermissionsWire = deserialize_mcp_apps_object(deserializer)?;
        Ok(Self {
            camera: wire.camera,
            microphone: wire.microphone,
            geolocation: wire.geolocation,
            clipboard_write: wire.clipboard_write,
        })
    }
}

/// Closed Apps rendering metadata attached to a `Resource` under `_meta.ui`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct McpAppsResourceMetadata {
    /// Optional CSP declarations for the rendered view.
    pub csp: Option<McpAppsResourceCsp>,
    /// Optional sandbox permission requests.
    pub permissions: Option<McpAppsResourcePermissions>,
    /// Optional host-defined dedicated view domain.
    pub domain: Option<String>,
    /// Whether the View prefers a visible host-provided border and background.
    pub prefers_border: Option<bool>,
}

impl McpAppsResourceMetadata {
    /// Creates closed non-security resource presentation metadata.
    #[must_use]
    pub const fn new(prefers_border: Option<bool>) -> Self {
        Self {
            csp: None,
            permissions: None,
            domain: None,
            prefers_border,
        }
    }

    /// Creates bounded resource rendering metadata with all currently stable
    /// Apps fields. The domain is retained as host-defined opaque data.
    pub fn try_new(
        csp: Option<McpAppsResourceCsp>,
        permissions: Option<McpAppsResourcePermissions>,
        domain: Option<String>,
        prefers_border: Option<bool>,
    ) -> Result<Self, McpAppsMetadataError> {
        if domain
            .as_deref()
            .is_some_and(|domain| domain.is_empty() || domain.len() > MAX_MCP_APPS_CSP_DOMAIN_BYTES)
        {
            return Err(McpAppsMetadataError::InvalidDomain);
        }
        Ok(Self {
            csp,
            permissions,
            domain,
            prefers_border,
        })
    }

    /// Produces a standalone final `_meta` object containing this exact nested
    /// Apps member.
    pub fn to_open_metadata(&self) -> Result<OpenMetadata, McpAppsMetadataError> {
        let value = serde_json::to_value(self)
            .map_err(|_| McpAppsMetadataError::InvalidResourceMetadata)?;
        OpenMetadata::try_from_entries([(MCP_APPS_UI_METADATA_KEY.to_owned(), value)])
            .map_err(|_| McpAppsMetadataError::InvalidResourceMetadata)
    }

    /// Merges this typed `ui` member into existing final open metadata.
    pub fn merge_into(
        &self,
        metadata: &OpenMetadata,
    ) -> Result<OpenMetadata, McpAppsMetadataError> {
        reject_deprecated_mcp_apps_metadata(metadata)?;
        if metadata.entries().contains_key(MCP_APPS_UI_METADATA_KEY) {
            return Err(McpAppsMetadataError::UiMetadataAlreadyPresent);
        }
        let mut entries = metadata.entries().clone();
        entries.insert(
            MCP_APPS_UI_METADATA_KEY.to_owned(),
            serde_json::to_value(self)
                .map_err(|_| McpAppsMetadataError::InvalidResourceMetadata)?,
        );
        OpenMetadata::try_from_entries(entries)
            .map_err(|_| McpAppsMetadataError::InvalidResourceMetadata)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct McpAppsResourceMetadataWire {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_mcp_apps_field"
    )]
    csp: Option<McpAppsResourceCsp>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_mcp_apps_field"
    )]
    permissions: Option<McpAppsResourcePermissions>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_mcp_apps_field"
    )]
    domain: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_mcp_apps_field"
    )]
    prefers_border: Option<bool>,
}

impl Serialize for McpAppsResourceMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        McpAppsResourceMetadataWire {
            csp: self.csp.clone(),
            permissions: self.permissions.clone(),
            domain: self.domain.clone(),
            prefers_border: self.prefers_border,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for McpAppsResourceMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire: McpAppsResourceMetadataWire = deserialize_mcp_apps_object(deserializer)?;
        Self::try_new(wire.csp, wire.permissions, wire.domain, wire.prefers_border)
            .map_err(serde::de::Error::custom)
    }
}

/// A validated association between a tool's nested Apps metadata and an HTML
/// UI resource in the final catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpAppsResourceBinding {
    /// Exact authority-form `ui://` resource URI selected by the tool.
    pub resource_uri: AbsoluteUri,
    /// The tool's effective Apps visibility.
    pub visibility: Vec<McpAppsToolVisibility>,
}

/// The exact document and effective metadata selected for one Apps View.
///
/// Construction through [`McpAppsResourceBinding::resolve_read_result`] binds
/// the document to its own metadata without copying its HTML or blob. The
/// original core result, including unrelated contents and open metadata,
/// remains untouched. These are resource requests for Host policy, not grants
/// of browser permissions or evidence of authorization.
pub struct McpAppsResourceRead<'a> {
    contents: &'a EmbeddedResourceContents,
    metadata: Option<McpAppsResourceMetadata>,
}

impl McpAppsResourceRead<'_> {
    /// The unique exact-URI HTML item, with its original wire metadata intact.
    #[must_use]
    pub const fn contents(&self) -> &EmbeddedResourceContents {
        self.contents
    }

    /// Effective typed metadata: a present read-item `ui` object replaces the
    /// entire listing object, including when it is empty. Listing fallback is
    /// possible only when the read-item `ui` member is absent.
    #[must_use]
    pub const fn metadata(&self) -> Option<&McpAppsResourceMetadata> {
        self.metadata.as_ref()
    }

    /// Compiles this exact document's effective CSP and permission requests
    /// against an explicit Host ceiling. The result is renderer-neutral data;
    /// it does not create a View, install browser policy or authorize a load.
    pub fn compile_sandbox_policy(
        &self,
        host: &McpAppsSandboxHostPolicy,
    ) -> Result<McpAppsSandboxPolicy, McpAppsSandboxPolicyError> {
        McpAppsSandboxPolicy::compile(self.metadata(), host)
    }
}

/// Origin policy for the Apps sandbox compiler. Cleartext loopback origins
/// require an explicit development policy; the default accepts no cleartext.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum McpAppsCspMode {
    #[default]
    Production,
    LocalDevelopment,
}

/// A CSP directive produced by the Apps sandbox compiler.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum McpAppsCspDirective {
    DefaultSrc,
    ScriptSrc,
    StyleSrc,
    ImgSrc,
    FontSrc,
    MediaSrc,
    ConnectSrc,
    FrameSrc,
    BaseUri,
    ObjectSrc,
}

impl McpAppsCspDirective {
    const ALL: [Self; 10] = [
        Self::DefaultSrc,
        Self::ScriptSrc,
        Self::StyleSrc,
        Self::ImgSrc,
        Self::FontSrc,
        Self::MediaSrc,
        Self::ConnectSrc,
        Self::FrameSrc,
        Self::BaseUri,
        Self::ObjectSrc,
    ];
    const RESOURCES: [Self; 5] = [
        Self::ScriptSrc,
        Self::StyleSrc,
        Self::ImgSrc,
        Self::FontSrc,
        Self::MediaSrc,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DefaultSrc => "default-src",
            Self::ScriptSrc => "script-src",
            Self::StyleSrc => "style-src",
            Self::ImgSrc => "img-src",
            Self::FontSrc => "font-src",
            Self::MediaSrc => "media-src",
            Self::ConnectSrc => "connect-src",
            Self::FrameSrc => "frame-src",
            Self::BaseUri => "base-uri",
            Self::ObjectSrc => "object-src",
        }
    }
}

/// A canonical CSP source token. Its private representation prevents peer
/// strings from being serialized as policy without source admission.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct McpAppsCspSource(String);

impl McpAppsCspSource {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_external(&self) -> bool {
        self.0 != "'self'" && self.0 != "'unsafe-inline'" && self.0 != "data:"
    }
}

/// The four permission-policy features supported by the pinned Apps schema.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum McpAppsSandboxPermission {
    Camera,
    Microphone,
    Geolocation,
    ClipboardWrite,
}

impl McpAppsSandboxPermission {
    const ALL: [Self; 4] = [
        Self::Camera,
        Self::Microphone,
        Self::Geolocation,
        Self::ClipboardWrite,
    ];

    /// Renderer-facing Permission Policy name, distinct from the wire's
    /// camelCase `clipboardWrite` member.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Camera => "camera",
            Self::Microphone => "microphone",
            Self::Geolocation => "geolocation",
            Self::ClipboardWrite => "clipboard-write",
        }
    }
}

/// Immutable Host ceilings for one sandbox compilation. The default denies
/// every source and permission. Builders admit only bounded canonical CSP
/// sources; a resource can request a subset but cannot expand this ceiling.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct McpAppsSandboxHostPolicy {
    mode: McpAppsCspMode,
    sources: BTreeMap<McpAppsCspDirective, BTreeSet<McpAppsCspSource>>,
    supported: BTreeSet<McpAppsSandboxPermission>,
    allowed: BTreeSet<McpAppsSandboxPermission>,
    consent_required: BTreeSet<McpAppsSandboxPermission>,
    consented: BTreeSet<McpAppsSandboxPermission>,
}

impl McpAppsSandboxHostPolicy {
    /// Chooses the immutable origin policy before adding any source.
    #[must_use]
    pub fn new(mode: McpAppsCspMode) -> Self {
        Self {
            mode,
            ..Self::default()
        }
    }

    /// Allows the pinned local source tokens, without allowing external
    /// domains, frames or browser permissions. The resource upper bound still
    /// applies: absent CSP cannot gain `connect-src 'self'` from this ceiling.
    #[must_use]
    pub fn allow_pinned_local_sources(mut self) -> Self {
        for directive in McpAppsCspDirective::RESOURCES {
            let sources = self.sources.entry(directive).or_default();
            sources.insert(McpAppsCspSource("'self'".to_owned()));
            if matches!(
                directive,
                McpAppsCspDirective::ScriptSrc | McpAppsCspDirective::StyleSrc
            ) {
                sources.insert(McpAppsCspSource("'unsafe-inline'".to_owned()));
            }
            if matches!(
                directive,
                McpAppsCspDirective::ImgSrc | McpAppsCspDirective::MediaSrc
            ) {
                sources.insert(McpAppsCspSource("data:".to_owned()));
            }
        }
        for directive in [
            McpAppsCspDirective::ConnectSrc,
            McpAppsCspDirective::BaseUri,
        ] {
            self.sources
                .entry(directive)
                .or_default()
                .insert(McpAppsCspSource("'self'".to_owned()));
        }
        self
    }

    /// Adds one external source to one Host directive ceiling. Source syntax
    /// is validated before storage; the unconditional default/object blocks
    /// cannot be relaxed. Wildcards are confined to resource directives.
    pub fn allow_source(
        mut self,
        directive: McpAppsCspDirective,
        source: &str,
    ) -> Result<Self, McpAppsSandboxPolicyError> {
        let source = parse_apps_csp_source(source, directive, self.mode)?;
        let sources = self.sources.entry(directive).or_default();
        if !sources.contains(&source)
            && sources.iter().filter(|source| source.is_external()).count()
                >= MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE
        {
            return Err(McpAppsSandboxPolicyError::TooManySources);
        }
        sources.insert(source);
        Ok(self)
    }

    /// Adds a resource origin to each of script/style/image/font/media.
    pub fn allow_resource_source(
        mut self,
        source: &str,
    ) -> Result<Self, McpAppsSandboxPolicyError> {
        for directive in McpAppsCspDirective::RESOURCES {
            self = self.allow_source(directive, source)?;
        }
        Ok(self)
    }

    /// Installs the Host's four independent permission layers. Resource
    /// markers are requests; a grant also needs installed support, deployment
    /// approval, and consent whenever the Host requires it.
    #[must_use]
    pub fn with_permissions(
        mut self,
        supported: impl IntoIterator<Item = McpAppsSandboxPermission>,
        allowed: impl IntoIterator<Item = McpAppsSandboxPermission>,
        consent_required: impl IntoIterator<Item = McpAppsSandboxPermission>,
        consented: impl IntoIterator<Item = McpAppsSandboxPermission>,
    ) -> Self {
        self.supported = supported.into_iter().collect();
        self.allowed = allowed.into_iter().collect();
        self.consent_required = consent_required.into_iter().collect();
        self.consented = consented.into_iter().collect();
        self
    }
}

/// Effective, monotonically restrictable sandbox policy. All directives are
/// explicit, including empty directives serialized as `'none'`. This is data
/// for an external renderer, not proof that browser enforcement is installed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpAppsSandboxPolicy {
    directives: BTreeMap<McpAppsCspDirective, BTreeSet<McpAppsCspSource>>,
    permissions: BTreeSet<McpAppsSandboxPermission>,
}

impl McpAppsSandboxPolicy {
    /// Compiles bounded, validated resource requests and intersects them with
    /// the Host ceiling. Omitted CSP and present-empty CSP keep their distinct
    /// pinned defaults. Domain identifiers, HTML conformance, user warnings,
    /// and browser installation remain separate Host responsibilities.
    pub fn compile(
        resource: Option<&McpAppsResourceMetadata>,
        host: &McpAppsSandboxHostPolicy,
    ) -> Result<Self, McpAppsSandboxPolicyError> {
        if resource
            .and_then(|resource| resource.domain.as_deref())
            .is_some_and(|domain| domain.is_empty() || domain.len() > MAX_MCP_APPS_CSP_DOMAIN_BYTES)
        {
            return Err(McpAppsSandboxPolicyError::InvalidMetadata);
        }
        let csp = resource.and_then(|resource| resource.csp.as_ref());
        let mut directives: BTreeMap<_, BTreeSet<_>> = McpAppsCspDirective::ALL
            .into_iter()
            .map(|directive| (directive, BTreeSet::new()))
            .collect();
        let local = McpAppsSandboxHostPolicy::default().allow_pinned_local_sources();
        for (directive, sources) in local.sources {
            if !matches!(
                directive,
                McpAppsCspDirective::ConnectSrc | McpAppsCspDirective::FontSrc
            ) || csp.is_some()
            {
                directives.insert(directive, sources);
            }
        }
        if let Some(csp) = csp {
            for (domains, targets) in [
                (
                    csp.connect_domains.as_deref(),
                    &[McpAppsCspDirective::ConnectSrc][..],
                ),
                (
                    csp.resource_domains.as_deref(),
                    &McpAppsCspDirective::RESOURCES[..],
                ),
                (
                    csp.frame_domains.as_deref(),
                    &[McpAppsCspDirective::FrameSrc][..],
                ),
                (
                    csp.base_uri_domains.as_deref(),
                    &[McpAppsCspDirective::BaseUri][..],
                ),
            ] {
                if domains
                    .is_some_and(|domains| domains.len() > MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE)
                {
                    return Err(McpAppsSandboxPolicyError::TooManySources);
                }
                if targets == [McpAppsCspDirective::BaseUri]
                    && domains.is_some_and(|domains| !domains.is_empty())
                {
                    directives
                        .get_mut(&McpAppsCspDirective::BaseUri)
                        .expect("all directives installed")
                        .clear();
                }
                for domain in domains.unwrap_or(&[]) {
                    for directive in targets {
                        let source = parse_apps_csp_source(domain, *directive, host.mode)?;
                        directives
                            .get_mut(directive)
                            .expect("all directives installed")
                            .insert(source);
                    }
                }
            }
        }
        for (directive, sources) in &mut directives {
            sources.retain(|source| {
                host.sources
                    .get(directive)
                    .is_some_and(|allowed| allowed.contains(source))
            });
        }
        let requested = resource.and_then(|resource| resource.permissions.as_ref());
        let permissions = McpAppsSandboxPermission::ALL
            .into_iter()
            .filter(|permission| {
                requested.is_some_and(|requested| match permission {
                    McpAppsSandboxPermission::Camera => requested.camera.is_some(),
                    McpAppsSandboxPermission::Microphone => requested.microphone.is_some(),
                    McpAppsSandboxPermission::Geolocation => requested.geolocation.is_some(),
                    McpAppsSandboxPermission::ClipboardWrite => requested.clipboard_write.is_some(),
                }) && host.supported.contains(permission)
                    && host.allowed.contains(permission)
                    && (!host.consent_required.contains(permission)
                        || host.consented.contains(permission))
            })
            .collect();
        Ok(Self {
            directives,
            permissions,
        })
    }

    /// Removes sources from an already compiled upper bound. Reapplying a
    /// more permissive predicate cannot restore a removed origin or keyword.
    #[must_use]
    pub fn restrict_sources(
        mut self,
        mut allow: impl FnMut(McpAppsCspDirective, &McpAppsCspSource) -> bool,
    ) -> Self {
        for (directive, sources) in &mut self.directives {
            sources.retain(|source| allow(*directive, source));
        }
        self
    }

    /// Withdraws effective grants without being able to add a new grant.
    #[must_use]
    pub fn restrict_permissions(
        mut self,
        mut allow: impl FnMut(McpAppsSandboxPermission) -> bool,
    ) -> Self {
        self.permissions.retain(|permission| allow(*permission));
        self
    }

    pub fn sources(
        &self,
        directive: McpAppsCspDirective,
    ) -> impl Iterator<Item = &McpAppsCspSource> {
        self.directives.get(&directive).into_iter().flatten()
    }

    #[must_use]
    pub fn permission_granted(&self, permission: McpAppsSandboxPermission) -> bool {
        self.permissions.contains(&permission)
    }

    /// Canonical CSP header value containing only compiler-owned directive
    /// names and admitted tokens. Empty sets are never omitted.
    #[must_use]
    pub fn csp_header_value(&self) -> String {
        self.directives
            .iter()
            .map(|(directive, sources)| {
                let sources = if sources.is_empty() {
                    "'none'".to_owned()
                } else {
                    sources
                        .iter()
                        .map(McpAppsCspSource::as_str)
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                format!("{} {sources}", directive.as_str())
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Exact wire grant set for this View. It is derived from the same
    /// intersection as renderer-facing permission queries.
    #[must_use]
    pub fn granted_permissions(&self) -> McpAppsResourcePermissions {
        let marker = |permission| {
            self.permission_granted(permission)
                .then(McpAppsResourcePermission::default)
        };
        McpAppsResourcePermissions {
            camera: marker(McpAppsSandboxPermission::Camera),
            microphone: marker(McpAppsSandboxPermission::Microphone),
            geolocation: marker(McpAppsSandboxPermission::Geolocation),
            clipboard_write: marker(McpAppsSandboxPermission::ClipboardWrite),
        }
    }

    /// Canonical external domains approved for the wire's four domain groups.
    /// A resource domain is advertised only if it survives in all five of its
    /// directives. The full CSP value remains the renderer's authority for
    /// local sources and restrictions that this domain-only schema cannot express.
    #[must_use]
    pub fn approved_domains(&self) -> McpAppsResourceCsp {
        let external = |directive| {
            self.sources(directive)
                .filter(|source| source.is_external())
                .map(|source| source.0.clone())
                .collect::<Vec<_>>()
        };
        let resources = self
            .sources(McpAppsCspDirective::ScriptSrc)
            .filter(|source| {
                source.is_external()
                    && McpAppsCspDirective::RESOURCES.iter().all(|directive| {
                        self.directives
                            .get(directive)
                            .is_some_and(|sources| sources.contains(*source))
                    })
            })
            .map(|source| source.0.clone())
            .collect();
        McpAppsResourceCsp {
            connect_domains: Some(external(McpAppsCspDirective::ConnectSrc)),
            resource_domains: Some(resources),
            frame_domains: Some(external(McpAppsCspDirective::FrameSrc)),
            base_uri_domains: Some(external(McpAppsCspDirective::BaseUri)),
        }
    }
}

/// Redacted compilation failures; raw origins, HTML and permission claims are
/// never embedded in diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpAppsSandboxPolicyError {
    InvalidSource,
    TooManySources,
    InvalidMetadata,
}

impl fmt::Display for McpAppsSandboxPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSource => "invalid MCP Apps sandbox source",
            Self::TooManySources => "MCP Apps sandbox source limit exceeded",
            Self::InvalidMetadata => "invalid MCP Apps sandbox metadata",
        })
    }
}

impl std::error::Error for McpAppsSandboxPolicyError {}

fn parse_apps_csp_source(
    value: &str,
    directive: McpAppsCspDirective,
    mode: McpAppsCspMode,
) -> Result<McpAppsCspSource, McpAppsSandboxPolicyError> {
    let invalid = || McpAppsSandboxPolicyError::InvalidSource;
    if value.is_empty()
        || value.len() > MAX_MCP_APPS_CSP_DOMAIN_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || matches!(
            directive,
            McpAppsCspDirective::DefaultSrc | McpAppsCspDirective::ObjectSrc
        )
    {
        return Err(invalid());
    }
    let (scheme, authority) = value.split_once("://").ok_or_else(invalid)?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.contains(['/', '@', '?', '#', '\\', '%', ';', '\'']) {
        return Err(invalid());
    }
    let (raw_host, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or_else(invalid)?;
        let suffix = &authority[end + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or_else(invalid)?)
        };
        (&authority[..=end], port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let (wildcard, host) = raw_host
        .strip_prefix("*.")
        .map_or((false, raw_host), |host| (true, host));
    let host = if let Some(literal) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        let address: std::net::Ipv6Addr = literal.parse().map_err(|_| invalid())?;
        if wildcard || address.to_string() != literal {
            return Err(invalid());
        }
        format!("[{address}]")
    } else if let Ok(address) = host.parse::<std::net::Ipv4Addr>() {
        if wildcard || address.to_string() != host {
            return Err(invalid());
        }
        address.to_string()
    } else {
        let host = host.to_ascii_lowercase();
        let last = host.rsplit('.').next().ok_or_else(invalid)?;
        let numeric = !last.is_empty()
            && (last.bytes().all(|byte| byte.is_ascii_digit())
                || last
                    .strip_prefix("0x")
                    .is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit())));
        if numeric
            || host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with("xn--")
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(invalid());
        }
        host
    };
    let loopback = matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]");
    let connect = directive == McpAppsCspDirective::ConnectSrc;
    let secure = scheme == "https" || (connect && scheme == "wss");
    let development = mode == McpAppsCspMode::LocalDevelopment
        && loopback
        && !wildcard
        && (scheme == "http" || (connect && scheme == "ws"));
    if !(secure || development)
        || (wildcard && (scheme != "https" || !McpAppsCspDirective::RESOURCES.contains(&directive)))
    {
        return Err(invalid());
    }
    let port = port
        .map(|port| {
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid());
            }
            port.parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(invalid)
        })
        .transpose()?;
    let default_port = if secure { 443 } else { 80 };
    let port = port
        .filter(|port| *port != default_port)
        .map_or_else(String::new, |port| format!(":{port}"));
    Ok(McpAppsCspSource(format!(
        "{scheme}://{}{host}{port}",
        if wildcard { "*." } else { "" }
    )))
}

impl fmt::Debug for McpAppsResourceRead<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpAppsResourceRead")
            .field("has_metadata", &self.metadata.is_some())
            .finish_non_exhaustive()
    }
}

impl McpAppsResourceBinding {
    /// Derives a binding only when the tool declares a nested Apps resource URI.
    pub fn from_tool(tool: &FinalTool) -> Result<Option<Self>, McpAppsMetadataError> {
        let Some(metadata) = tool.mcp_apps_metadata()? else {
            return Ok(None);
        };
        let visibility = metadata.effective_visibility().to_vec();
        let Some(resource_uri) = metadata.resource_uri else {
            return Ok(None);
        };
        Ok(Some(Self {
            resource_uri,
            visibility,
        }))
    }

    /// Verifies that a catalog resource is the exact HTML resource selected by
    /// this binding. Resource presentation metadata remains optional.
    pub fn validate_resource(
        &self,
        resource: &FinalResource,
    ) -> Result<(), McpAppsResourceBindingError> {
        let _ = resource
            .mcp_apps_metadata()
            .map_err(McpAppsResourceBindingError::Metadata)?;
        if resource.uri != self.resource_uri {
            return Err(McpAppsResourceBindingError::UriMismatch);
        }
        if resource.mime_type.as_deref() != Some(MCP_APPS_HTML_MIME_TYPE) {
            return Err(McpAppsResourceBindingError::HtmlMimeTypeRequired);
        }
        Ok(())
    }

    /// Selects an Apps document from an ordinarily admitted, complete resource
    /// read made through the originating authenticated MCP server.
    ///
    /// Exactly one content item must match the linked URI byte for byte, and
    /// that item must use the exact Apps HTML MIME type. Other items cannot
    /// supply its content, MIME type or metadata. A present read-item `ui`
    /// object wins wholesale; invalid, null or oversized metadata never falls
    /// back to a catalog entry. If `ui` is absent, only an exact-URI Apps catalog
    /// entry may supply metadata. No field-wise merging is performed.
    ///
    /// This method performs no network access, Apps activation, authorization,
    /// blob decoding or HTML rendering. Ordinary core admission owns complete
    /// message/byte bounds; selection additionally bounds its item traversal.
    pub fn resolve_read_result<'a>(
        &self,
        result: &'a FinalReadResourceResult,
        listed: Option<&FinalResource>,
    ) -> Result<McpAppsResourceRead<'a>, McpAppsResourceBindingError> {
        if !self.resource_uri.as_str().starts_with("ui://") {
            return Err(McpAppsResourceBindingError::Metadata(
                McpAppsMetadataError::ResourceUriMustUseUiPrefix,
            ));
        }
        if result.contents.len() > MAX_RESULT_CONTAINER_MEMBERS {
            return Err(McpAppsResourceBindingError::ReadResultTooLarge);
        }
        let mut selected = None;
        for contents in &result.contents {
            let (uri, mime_type, metadata) = match contents {
                EmbeddedResourceContents::Text {
                    uri,
                    mime_type,
                    meta,
                    ..
                }
                | EmbeddedResourceContents::Blob {
                    uri,
                    mime_type,
                    meta,
                    ..
                } => (uri, mime_type, meta),
            };
            if uri != &self.resource_uri {
                continue;
            }
            if selected.is_some() {
                return Err(McpAppsResourceBindingError::DuplicateReadResource);
            }
            selected = Some((contents, mime_type, metadata));
        }
        let (contents, mime_type, metadata) =
            selected.ok_or(McpAppsResourceBindingError::MissingReadResource)?;
        if mime_type.as_deref() != Some(MCP_APPS_HTML_MIME_TYPE) {
            return Err(McpAppsResourceBindingError::HtmlMimeTypeRequired);
        }
        let read_metadata = metadata
            .as_ref()
            .map(parse_mcp_apps_resource_metadata)
            .transpose()
            .map_err(McpAppsResourceBindingError::Metadata)?
            .flatten();
        let metadata = match (read_metadata, listed) {
            (Some(metadata), _) => Some(metadata),
            (None, Some(listed)) => {
                self.validate_resource(listed)?;
                listed
                    .mcp_apps_metadata()
                    .map_err(McpAppsResourceBindingError::Metadata)?
            }
            (None, None) => None,
        };
        Ok(McpAppsResourceRead { contents, metadata })
    }
}

/// A View lifecycle phase. This pure protocol state machine does not send or
/// receive any `ui/*` RPC message; a future bridge runtime owns that work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpAppsViewLifecycle {
    /// No initialization attempt has been admitted.
    New,
    /// One initialization request is reserved and awaiting its response.
    InitializeInFlight,
    /// Initialization succeeded and the initialized notification is due.
    AwaitingInitialized,
    /// The View may receive ordinary application traffic.
    Active,
    /// Terminal teardown has begun.
    Closing,
    /// Terminal teardown is complete.
    Closed,
}

impl Default for McpAppsViewLifecycle {
    fn default() -> Self {
        Self::New
    }
}

impl McpAppsViewLifecycle {
    /// Reserves the single legal initialization attempt.
    pub fn begin_initialize(&mut self) -> Result<(), McpAppsLifecycleError> {
        self.transition(Self::New, Self::InitializeInFlight, "initialize")
    }

    /// Commits a successful initialization response.
    pub fn initialization_succeeded(&mut self) -> Result<(), McpAppsLifecycleError> {
        self.transition(
            Self::InitializeInFlight,
            Self::AwaitingInitialized,
            "initialize response",
        )
    }

    /// Atomically rolls a failed initialization back before exposure.
    pub fn initialization_failed(&mut self) -> Result<(), McpAppsLifecycleError> {
        self.transition(Self::InitializeInFlight, Self::New, "initialize rollback")
    }

    /// Admits the sole initialized notification and enables application traffic.
    pub fn admit_initialized(&mut self) -> Result<(), McpAppsLifecycleError> {
        self.transition(
            Self::AwaitingInitialized,
            Self::Active,
            "initialized notification",
        )
    }

    /// Begins one terminal teardown from every non-terminal phase.
    pub fn begin_closing(&mut self) -> Result<(), McpAppsLifecycleError> {
        match *self {
            Self::New | Self::InitializeInFlight | Self::AwaitingInitialized | Self::Active => {
                *self = Self::Closing;
                Ok(())
            }
            Self::Closing | Self::Closed => Err(McpAppsLifecycleError::InvalidTransition {
                from: *self,
                operation: "begin closing",
            }),
        }
    }

    /// Completes one terminal teardown.
    pub fn finish_closing(&mut self) -> Result<(), McpAppsLifecycleError> {
        self.transition(Self::Closing, Self::Closed, "finish closing")
    }

    /// Returns whether ordinary Host/View application traffic is legal.
    #[must_use]
    pub const fn permits_application_traffic(self) -> bool {
        matches!(self, Self::Active)
    }

    fn transition(
        &mut self,
        expected: Self,
        next: Self,
        operation: &'static str,
    ) -> Result<(), McpAppsLifecycleError> {
        if *self != expected {
            return Err(McpAppsLifecycleError::InvalidTransition {
                from: *self,
                operation,
            });
        }
        *self = next;
        Ok(())
    }
}

/// One validated Apps-side projection of a complete final `tools/call` result.
///
/// This projection intentionally accepts only the complete final result
/// branch. Tasks and MRTR input-required branches remain outside the Apps
/// bridge until an explicit composition contract is implemented.
#[derive(Clone, Debug, PartialEq)]
pub struct McpAppsToolResult {
    /// Complete final content projected without normalization.
    pub content: Vec<ContentBlock>,
    /// Tool-level error indicator retained exactly.
    pub is_error: bool,
    /// Optional structured output, including an explicitly present JSON null.
    pub structured_content: Option<serde_json::Value>,
}

impl McpAppsToolResult {
    /// Constructs a bounded Apps result projection.
    pub fn try_new(
        content: Vec<ContentBlock>,
        is_error: bool,
        structured_content: Option<serde_json::Value>,
    ) -> Result<Self, McpAppsResultProjectionError> {
        if content.len() > MAX_RESULT_CONTAINER_MEMBERS {
            return Err(McpAppsResultProjectionError::ResultTooLarge);
        }
        let result = Self {
            content,
            is_error,
            structured_content,
        };
        let encoded = serde_json::to_vec(&McpAppsToolResultWire::from(&result))
            .map_err(|_| McpAppsResultProjectionError::ResultTooLarge)?;
        if encoded.len() > MAX_RESULT_ENCODED_BYTES {
            return Err(McpAppsResultProjectionError::ResultTooLarge);
        }
        Ok(result)
    }

    /// Projects one fully validated final `tools/call` payload exactly once.
    pub fn from_final_call_tool_result(
        result: &FinalCallToolResult,
    ) -> Result<Self, McpAppsResultProjectionError> {
        Self::try_new(
            result.content.clone(),
            result.is_error,
            result.structured_content.clone(),
        )
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct McpAppsToolResultWire {
    content: Vec<ContentBlock>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    is_error: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_apps_present_json_value")]
    structured_content: Option<serde_json::Value>,
}

fn deserialize_apps_present_json_value<'de, D>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde_json::Value::deserialize(deserializer).map(Some)
}

impl From<&McpAppsToolResult> for McpAppsToolResultWire {
    fn from(result: &McpAppsToolResult) -> Self {
        Self {
            content: result.content.clone(),
            is_error: result.is_error,
            structured_content: result.structured_content.clone(),
        }
    }
}

impl Serialize for McpAppsToolResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Self::try_new(
            self.content.clone(),
            self.is_error,
            self.structured_content.clone(),
        )
        .map_err(serde::ser::Error::custom)?;
        McpAppsToolResultWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for McpAppsToolResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = McpAppsToolResultWire::deserialize(deserializer)?;
        Self::try_new(wire.content, wire.is_error, wire.structured_content)
            .map_err(serde::de::Error::custom)
    }
}

/// Projects the complete `tools/call` branch while rejecting deferred Tasks and
/// MRTR branches before any Apps result is produced.
pub fn project_final_core_tools_call_result(
    result: &FinalCoreResult,
) -> Result<McpAppsToolResult, McpAppsResultProjectionError> {
    match result {
        FinalCoreResult::ToolsCall { result, .. } => {
            McpAppsToolResult::from_final_call_tool_result(&result.payload)
        }
        #[cfg(feature = "tasks")]
        FinalCoreResult::ToolsCallTask { .. } => {
            Err(McpAppsResultProjectionError::TasksUnsupported)
        }
        FinalCoreResult::ToolsCallInputRequired { .. } => {
            Err(McpAppsResultProjectionError::MrtrUnsupported)
        }
        _ => Err(McpAppsResultProjectionError::NotToolsCall),
    }
}

/// Metadata validation failures specific to the closed Apps `ui` member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpAppsMetadataError {
    /// The old flat `ui/resourceUri` key is forbidden on the final surface.
    DeprecatedFlatResourceUri,
    /// The nested `ui` member was not an object.
    UiMetadataMustBeObject,
    /// A tool `ui` object did not satisfy its closed schema.
    InvalidToolMetadata,
    /// A resource `ui` object did not satisfy its closed schema.
    InvalidResourceMetadata,
    /// A resource binding URI must start with the exact `ui://` prefix.
    ResourceUriMustUseUiPrefix,
    /// A tool visibility declaration carried more than its bounded number of entries.
    TooManyToolVisibilityEntries,
    /// One CSP directive carried more than its bounded number of origins.
    TooManyCspDomains,
    /// One CSP origin was empty or exceeded its bounded byte allowance.
    InvalidCspDomain,
    /// The host-defined Apps domain was empty or exceeded its bounded allowance.
    InvalidDomain,
    /// A merge would overwrite a pre-existing nested `ui` member.
    UiMetadataAlreadyPresent,
}

impl fmt::Display for McpAppsMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeprecatedFlatResourceUri => formatter.write_str(
                "deprecated flat MCP Apps metadata key ui/resourceUri is forbidden; use _meta.ui.resourceUri",
            ),
            Self::UiMetadataMustBeObject => {
                formatter.write_str("MCP Apps _meta.ui must be an object")
            }
            Self::InvalidToolMetadata => {
                formatter.write_str("MCP Apps tool _meta.ui does not satisfy its closed schema")
            }
            Self::InvalidResourceMetadata => formatter
                .write_str("MCP Apps resource _meta.ui does not satisfy its closed schema"),
            Self::ResourceUriMustUseUiPrefix => {
                formatter.write_str("MCP Apps resourceUri must start with ui://")
            }
            Self::TooManyToolVisibilityEntries => {
                formatter.write_str("MCP Apps tool visibility exceeds its entry limit")
            }
            Self::TooManyCspDomains => {
                formatter.write_str("MCP Apps CSP directive exceeds its origin limit")
            }
            Self::InvalidCspDomain => {
                formatter.write_str("MCP Apps CSP origin is empty or exceeds its byte limit")
            }
            Self::InvalidDomain => {
                formatter.write_str("MCP Apps domain is empty or exceeds its byte limit")
            }
            Self::UiMetadataAlreadyPresent => {
                formatter.write_str("MCP Apps _meta already contains a ui member")
            }
        }
    }
}

impl std::error::Error for McpAppsMetadataError {}

/// A catalog or read resource did not satisfy one validated Apps binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpAppsResourceBindingError {
    /// The candidate resource URI differs from the tool's exact binding URI.
    UriMismatch,
    /// The candidate resource is not an Apps HTML resource.
    HtmlMimeTypeRequired,
    /// No item in the complete read result matches the linked resource URI.
    MissingReadResource,
    /// Multiple read items match, even if their content is identical.
    DuplicateReadResource,
    /// The read result exceeds the bounded content-item traversal.
    ReadResultTooLarge,
    /// Resource metadata was not a valid closed Apps metadata object.
    Metadata(McpAppsMetadataError),
}

impl fmt::Display for McpAppsResourceBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UriMismatch => {
                formatter.write_str("MCP Apps resource URI differs from tool binding")
            }
            Self::HtmlMimeTypeRequired => {
                formatter.write_str("MCP Apps bound resource must use text/html;profile=mcp-app")
            }
            Self::MissingReadResource => {
                formatter.write_str("MCP Apps read result has no exact bound resource")
            }
            Self::DuplicateReadResource => {
                formatter.write_str("MCP Apps read result has multiple exact bound resources")
            }
            Self::ReadResultTooLarge => {
                formatter.write_str("MCP Apps read result exceeds its content-item bound")
            }
            Self::Metadata(error) => write!(formatter, "MCP Apps resource metadata: {error}"),
        }
    }
}

impl std::error::Error for McpAppsResourceBindingError {}

/// Illegal transition in the pure Apps View lifecycle state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpAppsLifecycleError {
    /// The requested operation is not legal from the retained lifecycle phase.
    InvalidTransition {
        /// Current lifecycle phase.
        from: McpAppsViewLifecycle,
        /// Name of the rejected operation.
        operation: &'static str,
    },
}

impl fmt::Display for McpAppsLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, operation } => {
                write!(
                    formatter,
                    "MCP Apps lifecycle cannot {operation} from {from:?}"
                )
            }
        }
    }
}

impl std::error::Error for McpAppsLifecycleError {}

/// Apps result projection failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpAppsResultProjectionError {
    /// The projected result exceeds the final result bounds.
    ResultTooLarge,
    /// A Tasks-backed `tools/call` result has no Apps result composition.
    TasksUnsupported,
    /// An MRTR `input_required` tools/call result has no Apps result composition.
    MrtrUnsupported,
    /// Only the final `tools/call` result family can be projected.
    NotToolsCall,
}

impl fmt::Display for McpAppsResultProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResultTooLarge => {
                formatter.write_str("MCP Apps result exceeds final result bounds")
            }
            Self::TasksUnsupported => {
                formatter.write_str("MCP Apps does not project Tasks-backed tool results")
            }
            Self::MrtrUnsupported => {
                formatter.write_str("MCP Apps does not project MRTR input-required tool results")
            }
            Self::NotToolsCall => {
                formatter.write_str("MCP Apps projects only final tools/call results")
            }
        }
    }
}

impl std::error::Error for McpAppsResultProjectionError {}

fn validate_mcp_apps_domains(domains: Option<&[String]>) -> Result<(), McpAppsMetadataError> {
    let Some(domains) = domains else {
        return Ok(());
    };
    if domains.len() > MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE {
        return Err(McpAppsMetadataError::TooManyCspDomains);
    }
    if domains
        .iter()
        .any(|domain| domain.is_empty() || domain.len() > MAX_MCP_APPS_CSP_DOMAIN_BYTES)
    {
        return Err(McpAppsMetadataError::InvalidCspDomain);
    }
    Ok(())
}

fn reject_deprecated_mcp_apps_metadata(
    metadata: &OpenMetadata,
) -> Result<(), McpAppsMetadataError> {
    if metadata
        .entries()
        .contains_key(MCP_APPS_DEPRECATED_RESOURCE_URI_METADATA_KEY)
    {
        Err(McpAppsMetadataError::DeprecatedFlatResourceUri)
    } else {
        Ok(())
    }
}

fn parse_mcp_apps_tool_metadata(
    metadata: &OpenMetadata,
) -> Result<Option<McpAppsToolMetadata>, McpAppsMetadataError> {
    reject_deprecated_mcp_apps_metadata(metadata)?;
    let Some(value) = metadata.entries().get(MCP_APPS_UI_METADATA_KEY) else {
        return Ok(None);
    };
    if !value.is_object() {
        return Err(McpAppsMetadataError::UiMetadataMustBeObject);
    }
    let metadata = serde_json::from_value(value.clone())
        .map_err(|_| McpAppsMetadataError::InvalidToolMetadata)?;
    Ok(Some(metadata))
}

fn parse_mcp_apps_resource_metadata(
    metadata: &OpenMetadata,
) -> Result<Option<McpAppsResourceMetadata>, McpAppsMetadataError> {
    reject_deprecated_mcp_apps_metadata(metadata)?;
    let Some(value) = metadata.entries().get(MCP_APPS_UI_METADATA_KEY) else {
        return Ok(None);
    };
    if !value.is_object() {
        return Err(McpAppsMetadataError::UiMetadataMustBeObject);
    }
    let metadata = serde_json::from_value(value.clone())
        .map_err(|_| McpAppsMetadataError::InvalidResourceMetadata)?;
    Ok(Some(metadata))
}

fn serialize_final_tool_metadata<S>(
    metadata: &Option<OpenMetadata>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if let Some(metadata) = metadata {
        parse_mcp_apps_tool_metadata(metadata).map_err(serde::ser::Error::custom)?;
    }
    metadata.serialize(serializer)
}

fn deserialize_final_tool_metadata<'de, D>(
    deserializer: D,
) -> Result<Option<OpenMetadata>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let metadata = Option::<OpenMetadata>::deserialize(deserializer)?;
    if let Some(metadata) = &metadata {
        parse_mcp_apps_tool_metadata(metadata).map_err(serde::de::Error::custom)?;
    }
    Ok(metadata)
}

fn serialize_final_resource_metadata<S>(
    metadata: &Option<OpenMetadata>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if let Some(metadata) = metadata {
        parse_mcp_apps_resource_metadata(metadata).map_err(serde::ser::Error::custom)?;
    }
    metadata.serialize(serializer)
}

fn deserialize_final_resource_metadata<'de, D>(
    deserializer: D,
) -> Result<Option<OpenMetadata>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let metadata = Option::<OpenMetadata>::deserialize(deserializer)?;
    if let Some(metadata) = &metadata {
        parse_mcp_apps_resource_metadata(metadata).map_err(serde::de::Error::custom)?;
    }
    Ok(metadata)
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
    #[serde(
        rename = "_meta",
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_final_tool_metadata",
        deserialize_with = "deserialize_final_tool_metadata"
    )]
    pub meta: Option<OpenMetadata>,
}

impl FinalTool {
    /// Reads and validates the tool's optional closed `_meta.ui` Apps member.
    pub fn mcp_apps_metadata(&self) -> Result<Option<McpAppsToolMetadata>, McpAppsMetadataError> {
        self.meta
            .as_ref()
            .map_or(Ok(None), parse_mcp_apps_tool_metadata)
    }

    /// Derives the optional exact Apps resource binding declared by this tool.
    pub fn mcp_apps_resource_binding(
        &self,
    ) -> Result<Option<McpAppsResourceBinding>, McpAppsMetadataError> {
        McpAppsResourceBinding::from_tool(self)
    }
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
    pub size: Option<JsonInteger>,
    /// Optional client-facing annotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Annotations>,
    /// Optional final metadata.
    #[serde(
        rename = "_meta",
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_final_resource_metadata",
        deserialize_with = "deserialize_final_resource_metadata"
    )]
    pub meta: Option<OpenMetadata>,
}

impl FinalResource {
    /// Reads and validates the resource's optional closed `_meta.ui` Apps
    /// presentation member.
    pub fn mcp_apps_metadata(
        &self,
    ) -> Result<Option<McpAppsResourceMetadata>, McpAppsMetadataError> {
        self.meta
            .as_ref()
            .map_or(Ok(None), parse_mcp_apps_resource_metadata)
    }
}

/// Exact final `ResourceTemplate` model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalResourceTemplate {
    /// RFC 6570 resource URI template.
    #[serde(
        rename = "uriTemplate",
        serialize_with = "serialize_final_resource_uri_template",
        deserialize_with = "deserialize_final_resource_uri_template"
    )]
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

fn deserialize_final_resource_uri_template<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    crate::UriTemplate::parse(&value)
        .map(|_| value)
        .map_err(D::Error::custom)
}

fn serialize_final_resource_uri_template<S>(
    value: &String,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    crate::UriTemplate::parse(value).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(value)
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

impl From<fastmcp_core::SamplingRole> for Role {
    fn from(role: fastmcp_core::SamplingRole) -> Self {
        match role {
            fastmcp_core::SamplingRole::User => Self::User,
            fastmcp_core::SamplingRole::Assistant => Self::Assistant,
        }
    }
}

impl From<Role> for fastmcp_core::SamplingRole {
    fn from(role: Role) -> Self {
        match role {
            Role::User => Self::User,
            Role::Assistant => Self::Assistant,
        }
    }
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
/// Exact-2024 sampling can contain text or an image.
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

impl From<fastmcp_core::SamplingMessageContent> for SamplingContent {
    fn from(content: fastmcp_core::SamplingMessageContent) -> Self {
        match content {
            fastmcp_core::SamplingMessageContent::Text { text } => Self::Text { text },
            fastmcp_core::SamplingMessageContent::Image { data, mime_type } => {
                Self::Image { data, mime_type }
            }
        }
    }
}

impl From<SamplingContent> for fastmcp_core::SamplingMessageContent {
    fn from(content: SamplingContent) -> Self {
        match content {
            SamplingContent::Text { text } => Self::Text { text },
            SamplingContent::Image { data, mime_type } => Self::Image { data, mime_type },
        }
    }
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
            completions: Some(CompletionsCapability {}),
            tasks: Some(TasksCapability { list_changed: true }),
            ..Default::default()
        };
        let value = serde_json::to_value(&caps).expect("serialize");
        assert_eq!(value["tools"]["listChanged"], true);
        assert_eq!(value["resources"]["subscribe"], true);
        assert_eq!(value["resources"]["listChanged"], true);
        assert_eq!(value["prompts"]["listChanged"], true);
        assert!(value.get("logging").is_some());
        assert!(value.get("completions").is_some());
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
            completions: None,
            tasks: None,
            ..Default::default()
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
            sampling: Some(SamplingCapability::default()),
            elicitation: Some(ElicitationCapability::both()),
            roots: Some(RootsCapability { list_changed: true }),
            ..Default::default()
        };
        let value = serde_json::to_value(&caps).expect("serialize");
        assert!(value.get("sampling").is_some());
        assert!(value.get("elicitation").is_some());
        assert_eq!(value["roots"]["listChanged"], true);
    }

    #[test]
    fn client_capabilities_round_trip() {
        let caps = ClientCapabilities {
            sampling: Some(SamplingCapability::default()),
            elicitation: None,
            roots: Some(RootsCapability {
                list_changed: false,
            }),
            ..Default::default()
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

    #[test]
    fn resource_template_peer_admission_rejects_malformed_and_oversized_templates() {
        let accepted_wire = json!({
            "uriTemplate": "file://{path}",
            "name": "File Reader"
        });
        let accepted: ResourceTemplate = serde_json::from_value(accepted_wire.clone())
            .expect("a legal exact-2024 resource template remains admissible");
        assert_eq!(
            serde_json::to_value(accepted).expect("admitted template serializes"),
            accepted_wire
        );

        let mut malformed = accepted_wire.clone();
        malformed["uriTemplate"] = json!("file://{path");
        assert!(
            serde_json::from_value::<ResourceTemplate>(malformed).is_err(),
            "changing only the closing brace rejects malformed peer input"
        );

        let mut oversized = accepted_wire;
        oversized["uriTemplate"] = json!(format!(
            "mcp://{}",
            "x".repeat(crate::MAX_URI_TEMPLATE_BYTES)
        ));
        assert!(
            serde_json::from_value::<ResourceTemplate>(oversized).is_err(),
            "changing only the template length beyond the protocol bound rejects peer input"
        );
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
                assert_eq!(decoded.len(), 0);
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
    fn root_name_preserves_absent_empty_and_display_text() {
        for name in [
            None,
            Some(""),
            Some("Workspace <untrusted> https://example.test"),
        ] {
            let root = Root {
                uri: "file:///workspace/%41/./source".to_owned(),
                name: name.map(str::to_owned),
            };
            let value = serde_json::to_value(&root).expect("serialize root");
            assert_eq!(value.get("name").is_some(), name.is_some());
            assert_eq!(value["uri"], root.uri);
            let decoded: Root = serde_json::from_value(value.clone()).expect("decode root");
            assert_eq!(decoded, root);
            let payload = serde_json::json!({"roots": [value]});
            let embedded: crate::messages::FinalEmbeddedRootsListResult =
                serde_json::from_value(payload.clone()).expect("decode embedded roots");
            assert_eq!(embedded.roots, vec![root]);
            assert_eq!(serde_json::to_value(embedded).unwrap(), payload);
        }
    }

    #[test]
    fn root_name_rejects_null_and_non_string_values_in_embedded_results() {
        for name in [
            serde_json::Value::Null,
            serde_json::json!(false),
            serde_json::json!(42),
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            let root = serde_json::json!({"uri": "file:///workspace", "name": name});
            assert!(serde_json::from_value::<Root>(root.clone()).is_err());
            let payload = serde_json::json!({"roots": [root]});
            assert!(
                serde_json::from_value::<crate::messages::FinalEmbeddedRootsListResult>(
                    payload.clone()
                )
                .is_err()
            );
            assert!(
                serde_json::from_value::<crate::messages::FinalEmbeddedInputResponse>(payload)
                    .is_err()
            );
        }
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

    #[test]
    fn final_resource_size_preserves_arbitrary_width_and_rejects_fractional_values() {
        let accepted: serde_json::Value = serde_json::from_str(
            r#"{"uri":"file:///data.bin","name":"data","size":922337203685477580812345678901234567890}"#,
        )
        .expect("arbitrary-width resource size wire parses");
        let resource: FinalResource = serde_json::from_value(accepted.clone())
            .expect("arbitrary-width final resource size is accepted");
        assert_eq!(
            resource.size.as_ref().map(JsonInteger::as_str),
            Some("922337203685477580812345678901234567890")
        );
        assert_eq!(
            serde_json::to_value(resource).expect("arbitrary-width final resource re-encodes"),
            accepted,
            "the exact integer resource size lexeme round-trips"
        );

        let planted: serde_json::Value = serde_json::from_str(
            r#"{"uri":"file:///data.bin","name":"data","size":922337203685477580812345678901234567890.5}"#,
        )
        .expect("one-field fractional resource size wire parses");
        assert!(
            serde_json::from_value::<FinalResource>(planted).is_err(),
            "changing only the resource size to a fractional number rejects it"
        );
    }

    #[test]
    fn final_resource_template_enforces_the_uri_template_schema_format() {
        let accepted_wire = json!({
            "uriTemplate": "mcp://resources/{item:3}{?cursor,labels*}",
            "name": "resource-template"
        });
        let accepted: FinalResourceTemplate = serde_json::from_value(accepted_wire.clone())
            .expect("a final RFC 6570 Level 4 resource template is admitted");
        assert_eq!(
            accepted.uri_template, "mcp://resources/{item:3}{?cursor,labels*}",
            "typed final decoding preserves the accepted template spelling"
        );
        assert_eq!(
            serde_json::to_value(accepted).expect("accepted template re-encodes"),
            accepted_wire,
            "template validation does not normalize the final wire value"
        );

        let mut planted = accepted_wire;
        planted["uriTemplate"] = json!("mcp://resources/{item:0}");
        assert!(
            serde_json::from_value::<FinalResourceTemplate>(planted).is_err(),
            "changing only the prefix modifier to RFC 6570's forbidden zero rejects the template"
        );

        let locally_invalid = FinalResourceTemplate {
            uri_template: "mcp://resources/{item:0}".to_owned(),
            name: "resource-template".to_owned(),
            title: None,
            description: None,
            icons: None,
            mime_type: None,
            annotations: None,
            meta: None,
        };
        assert!(
            serde_json::to_value(locally_invalid).is_err(),
            "direct construction cannot serialize a URI template rejected at peer admission"
        );
    }

    #[test]
    fn apps_02_nested_tool_resource_metadata_and_result_projection_round_trip() {
        let tool_wire = json!({
            "name": "weather",
            "inputSchema": {"type": "object"},
            "_meta": {
                "ui": {
                    "resourceUri": "ui://weather/dashboard",
                    "visibility": ["model", "app"]
                },
                "com.example/catalog": "weather"
            }
        });
        let tool: FinalTool = serde_json::from_value(tool_wire.clone())
            .expect("a nested Apps tool resource binding is valid final metadata");
        let metadata = tool
            .mcp_apps_metadata()
            .expect("nested Apps tool metadata remains typed")
            .expect("the tool declares Apps metadata");
        assert_eq!(
            metadata.resource_uri.as_ref().map(AbsoluteUri::as_str),
            Some("ui://weather/dashboard")
        );
        assert_eq!(
            metadata.effective_visibility(),
            [McpAppsToolVisibility::Model, McpAppsToolVisibility::App]
        );
        assert_eq!(
            serde_json::to_value(&tool).expect("tool re-encodes exact nested metadata"),
            tool_wire
        );

        let resource_wire = json!({
            "uri": "ui://weather/dashboard",
            "name": "weather-dashboard",
            "mimeType": MCP_APPS_HTML_MIME_TYPE,
            "_meta": {"ui": {
                "csp": {
                    "connectDomains": ["https://api.weather.example"],
                    "resourceDomains": ["https://cdn.weather.example"],
                    "frameDomains": ["https://maps.weather.example"],
                    "baseUriDomains": ["https://cdn.weather.example"]
                },
                "permissions": {"geolocation": {}},
                "domain": "weather-view.host.example",
                "prefersBorder": true
            }}
        });
        let resource: FinalResource = serde_json::from_value(resource_wire.clone())
            .expect("an Apps HTML resource accepts nested presentation metadata");
        let resource_metadata = resource
            .mcp_apps_metadata()
            .expect("resource metadata remains typed")
            .expect("resource declares Apps presentation");
        assert_eq!(resource_metadata.prefers_border, Some(true));
        assert_eq!(
            resource_metadata
                .csp
                .as_ref()
                .and_then(|csp| csp.connect_domains.as_ref())
                .map(|domains| domains.iter().map(String::as_str).collect::<Vec<_>>()),
            Some(vec!["https://api.weather.example"])
        );
        assert!(
            resource_metadata
                .permissions
                .as_ref()
                .and_then(|permissions| permissions.geolocation.as_ref())
                .is_some()
        );
        assert_eq!(
            resource_metadata.domain.as_deref(),
            Some("weather-view.host.example")
        );
        tool.mcp_apps_resource_binding()
            .expect("tool metadata is valid")
            .expect("tool has an Apps binding")
            .validate_resource(&resource)
            .expect("the exact Apps HTML catalog resource satisfies the binding");
        assert_eq!(
            serde_json::to_value(&resource).expect("resource re-encodes exact nested metadata"),
            resource_wire
        );

        let final_result = FinalCallToolResult {
            content: vec![ContentBlock::text("sunny")],
            is_error: false,
            structured_content: Some(serde_json::Value::Null),
        };
        let projected = McpAppsToolResult::from_final_call_tool_result(&final_result)
            .expect("a complete final tools/call result projects into Apps content");
        let result_wire = json!({
            "content": [{"type": "text", "text": "sunny"}],
            "structuredContent": null
        });
        assert_eq!(
            serde_json::to_value(&projected).expect("Apps result serializes"),
            result_wire
        );
        assert_eq!(
            serde_json::from_value::<McpAppsToolResult>(result_wire)
                .expect("Apps result round-trips exactly"),
            projected
        );
    }

    #[test]
    fn apps_02_rejects_one_opaque_ui_uri_in_tool_metadata_construction_and_serde() {
        let accepted_uri = AbsoluteUri::parse("ui://opaque").expect("authority-form UI URI");
        let accepted = McpAppsToolMetadata::try_new(Some(accepted_uri), None)
            .expect("the exact UI URI is admitted");
        let accepted_wire = serde_json::json!({"resourceUri": "ui://opaque"});
        assert_eq!(
            serde_json::to_value(&accepted).expect("the admitted UI URI serializes"),
            accepted_wire,
        );

        let opaque_uri = AbsoluteUri::parse("ui:opaque").expect("opaque UI URI is absolute");
        assert_eq!(
            McpAppsToolMetadata::try_new(Some(opaque_uri.clone()), None),
            Err(McpAppsMetadataError::ResourceUriMustUseUiPrefix),
            "removing only the authority delimiter rejects constructor input"
        );
        let planted = McpAppsToolMetadata {
            resource_uri: Some(opaque_uri),
            visibility: None,
        };
        assert!(
            serde_json::to_value(&planted).is_err(),
            "direct construction cannot serialize an opaque ui: URI"
        );

        let mut opaque_wire = accepted_wire.clone();
        opaque_wire["resourceUri"] = serde_json::json!("ui:opaque");
        assert!(
            serde_json::from_value::<McpAppsToolMetadata>(opaque_wire).is_err(),
            "removing only the authority delimiter rejects deserialization"
        );
        assert_eq!(
            serde_json::to_value(&accepted).expect("rejected variants do not mutate the baseline"),
            accepted_wire,
        );
    }

    #[test]
    fn apps_02_rejects_only_deprecated_flat_resource_uri_metadata() {
        let accepted = json!({
            "name": "weather",
            "inputSchema": {"type": "object"},
            "_meta": {"ui": {"resourceUri": "ui://weather/dashboard"}}
        });
        let baseline: FinalTool = serde_json::from_value(accepted.clone())
            .expect("nested Apps resource metadata is the baseline");
        let mut planted = accepted.clone();
        let metadata = planted["_meta"]
            .as_object_mut()
            .expect("baseline metadata is an object");
        let nested = metadata
            .remove(MCP_APPS_UI_METADATA_KEY)
            .expect("baseline has nested Apps metadata");
        let resource_uri = nested["resourceUri"].clone();
        metadata.insert(
            MCP_APPS_DEPRECATED_RESOURCE_URI_METADATA_KEY.to_owned(),
            resource_uri,
        );

        assert!(
            serde_json::from_value::<FinalTool>(planted).is_err(),
            "only replacing nested ui.resourceUri with the deprecated flat key rejects the tool"
        );
        assert_eq!(
            serde_json::to_value(&baseline).expect("baseline remains serializable"),
            accepted,
            "the flat-key rejection cannot mutate the accepted nested binding"
        );
    }

    #[test]
    fn apps_02_rejects_one_csp_origin_beyond_the_bounded_directive_limit() {
        let accepted = json!({
            "uri": "ui://weather/dashboard",
            "name": "weather-dashboard",
            "mimeType": MCP_APPS_HTML_MIME_TYPE,
            "_meta": {"ui": {"csp": {
                "connectDomains": (0..MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE)
                    .map(|index| format!("https://{index}.weather.example"))
                    .collect::<Vec<_>>()
            }}}
        });
        let baseline: FinalResource = serde_json::from_value(accepted.clone())
            .expect("a bounded Apps CSP declaration is valid");
        let mut planted = accepted.clone();
        planted["_meta"]["ui"]["csp"]["connectDomains"]
            .as_array_mut()
            .expect("bounded baseline has a CSP origin array")
            .push(json!(format!(
                "https://{MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE}.weather.example"
            )));

        assert!(
            serde_json::from_value::<FinalResource>(planted).is_err(),
            "adding only one origin beyond the CSP directive bound rejects the resource metadata"
        );
        assert_eq!(
            serde_json::to_value(baseline).expect("bounded baseline re-encodes"),
            accepted,
            "the one-origin rejection cannot mutate the admitted Apps metadata"
        );
    }

    #[test]
    fn apps_02_direct_csp_construction_cannot_bypass_serialization_bounds() {
        let accepted = McpAppsResourceCsp {
            connect_domains: Some(
                (0..MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE)
                    .map(|index| format!("https://{index}.weather.example"))
                    .collect(),
            ),
            ..McpAppsResourceCsp::default()
        };
        let accepted_wire = serde_json::to_value(&accepted)
            .expect("the direct CSP value at the directive bound serializes");

        let mut planted = accepted.clone();
        planted
            .connect_domains
            .as_mut()
            .expect("the direct CSP fixture has connect domains")
            .push(format!(
                "https://{MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE}.weather.example"
            ));

        assert!(
            serde_json::to_value(&planted).is_err(),
            "adding only one domain beyond the bound rejects direct CSP serialization"
        );
        assert_eq!(
            serde_json::to_value(&accepted).expect("accepted direct CSP re-serializes"),
            accepted_wire,
            "a rejected direct CSP serialization cannot mutate the bounded baseline"
        );
    }

    #[test]
    fn apps_02_preserves_duplicate_and_ordered_visibility() {
        let accepted = json!({
            "name": "weather",
            "inputSchema": {"type": "object"},
            "_meta": {"ui": {"visibility": ["app", "model", "app"]}}
        });
        let tool: FinalTool = serde_json::from_value(accepted.clone())
            .expect("the stable Apps visibility array permits duplicates in wire order");
        let metadata = tool
            .mcp_apps_metadata()
            .expect("Apps metadata remains typed")
            .expect("the tool declares Apps metadata");
        assert_eq!(
            metadata.effective_visibility(),
            [
                McpAppsToolVisibility::App,
                McpAppsToolVisibility::Model,
                McpAppsToolVisibility::App,
            ],
            "Apps visibility preserves the received duplicate sequence"
        );
        assert_eq!(
            serde_json::to_value(&tool).expect("tool re-encodes"),
            accepted,
            "Apps visibility re-encodes duplicates in their received order"
        );
    }

    #[test]
    fn apps_02_bounds_tool_visibility_entries_without_changing_duplicates_or_order() {
        let accepted_visibility = (0..MAX_MCP_APPS_TOOL_VISIBILITY_ENTRIES)
            .map(|index| {
                if index % 2 == 0 {
                    McpAppsToolVisibility::App
                } else {
                    McpAppsToolVisibility::Model
                }
            })
            .collect::<Vec<_>>();
        let baseline = McpAppsToolMetadata::try_new(None, Some(accepted_visibility.clone()))
            .expect("the tool visibility entry bound is admitted");
        let baseline_wire =
            serde_json::to_value(&baseline).expect("bounded visibility metadata serializes");
        assert_eq!(
            baseline.effective_visibility(),
            accepted_visibility,
            "bounded visibility retains received duplicate entries in order"
        );

        let mut planted_visibility = accepted_visibility;
        planted_visibility.push(McpAppsToolVisibility::App);
        assert_eq!(
            McpAppsToolMetadata::try_new(None, Some(planted_visibility.clone())),
            Err(McpAppsMetadataError::TooManyToolVisibilityEntries),
            "adding only one visibility entry beyond the bound is rejected with the typed error"
        );
        let planted = McpAppsToolMetadata {
            resource_uri: None,
            visibility: Some(planted_visibility),
        };
        assert!(
            serde_json::to_value(&planted).is_err(),
            "direct construction cannot bypass the visibility entry bound during serialization"
        );
        assert_eq!(
            serde_json::to_value(&baseline).expect("bounded metadata re-serializes"),
            baseline_wire,
            "rejecting the one-entry plant cannot mutate the admitted metadata"
        );
    }

    #[test]
    fn apps_02_rejects_one_non_html_bound_resource_without_mutating_binding() {
        let tool: FinalTool = serde_json::from_value(json!({
            "name": "weather",
            "inputSchema": {"type": "object"},
            "_meta": {"ui": {"resourceUri": "ui://weather/dashboard"}}
        }))
        .expect("nested Apps binding is valid");
        let binding = tool
            .mcp_apps_resource_binding()
            .expect("tool metadata is valid")
            .expect("tool declares an Apps resource");
        let accepted = json!({
            "uri": "ui://weather/dashboard",
            "name": "weather-dashboard",
            "mimeType": MCP_APPS_HTML_MIME_TYPE
        });
        let baseline: FinalResource =
            serde_json::from_value(accepted.clone()).expect("Apps resource baseline decodes");
        let mut planted = accepted.clone();
        planted["mimeType"] = json!("text/plain");

        assert_eq!(binding.validate_resource(&baseline), Ok(()));
        let incompatible: FinalResource = serde_json::from_value(planted)
            .expect("only MIME type changes; resource remains a final resource");
        assert_eq!(
            binding.validate_resource(&incompatible),
            Err(McpAppsResourceBindingError::HtmlMimeTypeRequired),
            "only replacing the Apps HTML MIME type rejects the bound resource"
        );
        assert_eq!(
            serde_json::to_value(&baseline).expect("baseline resource re-encodes"),
            accepted,
            "the invalid resource cannot mutate the admitted binding target"
        );
    }

    fn apps_read_binding() -> McpAppsResourceBinding {
        let tool: FinalTool = serde_json::from_value(json!({
            "name": "weather", "inputSchema": {"type": "object"},
            "_meta": {"ui": {"resourceUri": "ui://weather/dashboard"}}
        }))
        .unwrap();
        tool.mcp_apps_resource_binding().unwrap().unwrap()
    }

    fn apps_read_item() -> serde_json::Value {
        json!({
            "uri": "ui://weather/dashboard", "mimeType": MCP_APPS_HTML_MIME_TYPE,
            "text": "<main>private document résumé 東京</main>"
        })
    }

    fn apps_read_result(contents: Vec<serde_json::Value>) -> FinalReadResourceResult {
        serde_json::from_value(json!({
            "contents": contents, "ttlMs": 25, "cacheScope": "private"
        }))
        .unwrap()
    }

    fn apps_read_listing() -> FinalResource {
        serde_json::from_value(json!({
            "uri": "ui://weather/dashboard", "name": "dashboard",
            "mimeType": MCP_APPS_HTML_MIME_TYPE,
            "_meta": {"ui": {
                "csp": {"connectDomains": ["https://api.example.test"]},
                "permissions": {"camera": {}},
                "domain": "private.host.example", "prefersBorder": true
            }}
        }))
        .unwrap()
    }

    #[test]
    fn apps_read_binding_selects_exact_text_and_blob_without_borrowing_other_items() {
        let binding = apps_read_binding();
        for blob in [false, true] {
            let mut selected = apps_read_item();
            if blob {
                selected.as_object_mut().unwrap().remove("text");
                selected["blob"] = json!("PG1haW4+SGk8L21haW4+");
            }
            selected["_meta"] = json!({"ui": {"prefersBorder": false}});
            let result = apps_read_result(vec![
                json!({
                    "uri": "ui://unrelated/document", "mimeType": MCP_APPS_HTML_MIME_TYPE,
                    "text": "other content", "_meta": {"ui": {"permissions": {"camera": null}}}
                }),
                selected.clone(),
            ]);
            let before = serde_json::to_value(&result).unwrap();
            let read = binding.resolve_read_result(&result, None).unwrap();
            assert!(std::ptr::eq(read.contents(), &raw const result.contents[1]));
            assert_eq!(serde_json::to_value(read.contents()).unwrap(), selected);
            assert_eq!(
                read.metadata(),
                Some(&McpAppsResourceMetadata::new(Some(false)))
            );
            assert!(!format!("{read:?}").contains("private document"));
            assert_eq!(serde_json::to_value(&result).unwrap(), before);
        }
    }

    #[test]
    fn apps_read_binding_resolves_presence_without_merging_catalog_policy() {
        let binding = apps_read_binding();
        let listing = apps_read_listing();
        let listing_metadata = listing.mcp_apps_metadata().unwrap().unwrap();
        for (read_meta, expected) in [
            (None, Some(listing_metadata.clone())),
            (
                Some(json!({"com.example/note": "inert"})),
                Some(listing_metadata),
            ),
            (
                Some(json!({"ui": {}})),
                Some(McpAppsResourceMetadata::default()),
            ),
            (
                Some(json!({"ui": {"prefersBorder": false}})),
                Some(McpAppsResourceMetadata::new(Some(false))),
            ),
        ] {
            let mut item = apps_read_item();
            if let Some(meta) = read_meta {
                item["_meta"] = meta;
            }
            let result = apps_read_result(vec![item]);
            let read = binding
                .resolve_read_result(&result, Some(&listing))
                .unwrap();
            assert_eq!(read.metadata(), expected.as_ref());
        }
        let result = apps_read_result(vec![apps_read_item()]);
        assert!(
            binding
                .resolve_read_result(&result, None)
                .unwrap()
                .metadata()
                .is_none()
        );

        let mut foreign_listing = listing;
        foreign_listing.uri = AbsoluteUri::parse("ui://other/dashboard").unwrap();
        assert_eq!(
            binding
                .resolve_read_result(&result, Some(&foreign_listing))
                .unwrap_err(),
            McpAppsResourceBindingError::UriMismatch
        );
        let mut authoritative = apps_read_item();
        authoritative["_meta"] = json!({"ui": {}});
        let result = apps_read_result(vec![authoritative]);
        assert_eq!(
            binding
                .resolve_read_result(&result, Some(&foreign_listing))
                .unwrap()
                .metadata(),
            Some(&McpAppsResourceMetadata::default()),
            "present read metadata must not inspect or inherit a stale catalog entry"
        );
    }

    #[test]
    fn apps_read_binding_rejects_invalid_policy_instead_of_catalog_fallback() {
        let binding = apps_read_binding();
        let listing = apps_read_listing();
        let mut invalid = vec![
            serde_json::Value::Null,
            json!([]),
            json!("policy"),
            json!({"csp": null}),
            json!({"permissions": null}),
            json!({"domain": null}),
            json!({"prefersBorder": null}),
            json!({"domain": ""}),
            json!({"unknown": true}),
            json!({"permissions": {"camera": {"grant": true}}}),
        ];
        for key in [
            "connectDomains",
            "resourceDomains",
            "frameDomains",
            "baseUriDomains",
        ] {
            invalid.push(json!({"csp": {key: null}}));
        }
        for key in ["camera", "microphone", "geolocation", "clipboardWrite"] {
            invalid.push(json!({"permissions": {key: null}}));
        }
        invalid.push(json!({"csp": {"connectDomains":
            vec!["https://api.example.test"; MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE + 1]
        }}));
        for ui in invalid {
            let mut item = apps_read_item();
            item["_meta"] = json!({"ui": ui});
            let result = apps_read_result(vec![item]);
            let before = serde_json::to_value(&result).unwrap();
            assert!(
                matches!(
                    binding.resolve_read_result(&result, Some(&listing)),
                    Err(McpAppsResourceBindingError::Metadata(_))
                ),
                "an invalid present policy cannot inherit the listing: {ui}"
            );
            assert_eq!(serde_json::to_value(&result).unwrap(), before);
        }
        let mut valid = apps_read_item();
        valid["_meta"] = json!({"ui": {"csp": {}, "permissions": {"camera": {}}}});
        let result = apps_read_result(vec![valid]);
        assert!(binding.resolve_read_result(&result, Some(&listing)).is_ok());
    }

    #[test]
    fn apps_read_binding_rejects_missing_duplicate_and_mismatched_documents() {
        let binding = apps_read_binding();
        let mut foreign = apps_read_item();
        foreign["uri"] = json!("ui://other/dashboard");
        let missing = apps_read_result(vec![foreign.clone()]);
        assert_eq!(
            binding.resolve_read_result(&missing, None).unwrap_err(),
            McpAppsResourceBindingError::MissingReadResource
        );
        for mime in [MCP_APPS_HTML_MIME_TYPE, "text/plain"] {
            let mut second = apps_read_item();
            second["mimeType"] = json!(mime);
            let duplicate = apps_read_result(vec![apps_read_item(), second]);
            assert_eq!(
                binding.resolve_read_result(&duplicate, None).unwrap_err(),
                McpAppsResourceBindingError::DuplicateReadResource
            );
        }
        let listing = apps_read_listing();
        let mut wrong_mime = apps_read_item();
        wrong_mime["mimeType"] = json!("text/html");
        let mismatched = apps_read_result(vec![wrong_mime, foreign]);
        assert_eq!(
            binding
                .resolve_read_result(&mismatched, Some(&listing))
                .unwrap_err(),
            McpAppsResourceBindingError::HtmlMimeTypeRequired
        );
        let mut too_large = apps_read_result(vec![apps_read_item()]);
        too_large.contents.resize(
            MAX_RESULT_CONTAINER_MEMBERS + 1,
            too_large.contents[0].clone(),
        );
        assert_eq!(
            binding.resolve_read_result(&too_large, None).unwrap_err(),
            McpAppsResourceBindingError::ReadResultTooLarge
        );
        let mut forged = binding;
        forged.resource_uri = AbsoluteUri::parse("https://example.test/dashboard").unwrap();
        assert!(matches!(
            forged.resolve_read_result(&missing, None),
            Err(McpAppsResourceBindingError::Metadata(
                McpAppsMetadataError::ResourceUriMustUseUiPrefix
            ))
        ));
    }

    #[test]
    fn apps_metadata_optional_fields_reject_explicit_null_but_preserve_empty_values() {
        for key in ["resourceUri", "visibility"] {
            assert!(serde_json::from_value::<McpAppsToolMetadata>(json!({key: null})).is_err());
        }
        assert!(serde_json::from_value::<McpAppsToolMetadata>(json!({"visibility": []})).is_ok());
        for ui in [
            json!({}),
            json!({"csp": {}, "permissions": {}}),
            json!({"prefersBorder": false}),
        ] {
            let metadata: McpAppsResourceMetadata = serde_json::from_value(ui.clone()).unwrap();
            assert_eq!(serde_json::to_value(metadata).unwrap(), ui);
        }
    }

    #[test]
    fn apps_metadata_structures_require_objects_in_json_values_and_wire_input() {
        fn assert_object_only<T: serde::de::DeserializeOwned + Serialize>(
            positional: serde_json::Value,
        ) {
            let accepted: T = serde_json::from_value(json!({})).unwrap();
            assert_eq!(serde_json::to_value(accepted).unwrap(), json!({}));
            let accepted: T = serde_json::from_str("{}").unwrap();
            assert_eq!(serde_json::to_value(accepted).unwrap(), json!({}));

            for invalid in [
                serde_json::Value::Null,
                json!(false),
                json!(42),
                json!("metadata"),
                json!([]),
                positional,
                json!({"unknown": {}}),
            ] {
                let wire = serde_json::to_string(&invalid).unwrap();
                assert!(
                    serde_json::from_value::<T>(invalid).is_err(),
                    "Apps metadata must be a closed object: {wire}"
                );
                assert!(
                    serde_json::from_str::<T>(&wire).is_err(),
                    "wire decoding must not accept positional or scalar metadata: {wire}"
                );
            }
        }

        assert_object_only::<McpAppsToolMetadata>(json!(["ui://weather/dashboard", []]));
        assert_object_only::<McpAppsResourceCsp>(json!([
            ["https://api.weather.example"],
            [],
            [],
            []
        ]));
        assert_object_only::<McpAppsResourcePermission>(json!([{}]));
        assert_object_only::<McpAppsResourcePermissions>(json!([{}, {}, {}, {}]));
        assert_object_only::<McpAppsResourceMetadata>(json!([{}, {}, "view.host.example", false]));
    }

    #[test]
    fn apps_read_binding_rejects_non_object_policy_components_without_fallback() {
        let binding = apps_read_binding();
        let listing = apps_read_listing();

        for field in ["csp", "permissions"] {
            for invalid in [
                json!([]),
                json!([{}]),
                json!(false),
                json!(42),
                json!("policy"),
            ] {
                let mut item = apps_read_item();
                item["_meta"] = json!({"ui": {field: invalid}});
                let result = apps_read_result(vec![item]);
                assert!(matches!(
                    binding.resolve_read_result(&result, Some(&listing)),
                    Err(McpAppsResourceBindingError::Metadata(_))
                ));
            }
            let mut item = apps_read_item();
            item["_meta"] = json!({"ui": {field: {}}});
            let result = apps_read_result(vec![item]);
            let read = binding
                .resolve_read_result(&result, Some(&listing))
                .unwrap();
            assert_eq!(
                serde_json::to_value(read.metadata().unwrap()).unwrap(),
                json!({field: {}})
            );
        }

        for permission in ["camera", "microphone", "geolocation", "clipboardWrite"] {
            for invalid in [
                json!([]),
                json!([{}]),
                json!(false),
                json!(42),
                json!("marker"),
            ] {
                let mut item = apps_read_item();
                item["_meta"] = json!({"ui": {"permissions": {permission: invalid}}});
                let result = apps_read_result(vec![item]);
                assert!(matches!(
                    binding.resolve_read_result(&result, Some(&listing)),
                    Err(McpAppsResourceBindingError::Metadata(_))
                ));
            }
            let mut item = apps_read_item();
            item["_meta"] = json!({"ui": {"permissions": {permission: {}}}});
            let result = apps_read_result(vec![item]);
            let read = binding
                .resolve_read_result(&result, Some(&listing))
                .unwrap();
            assert_eq!(
                serde_json::to_value(read.metadata().unwrap()).unwrap(),
                json!({"permissions": {permission: {}}}),
                "only the valid empty object is a permission request marker"
            );
        }
    }

    #[test]
    fn apps_metadata_object_decoders_preserve_duplicate_field_rejections() {
        assert!(
            serde_json::from_str::<McpAppsToolMetadata>(r#"{"visibility":[],"visibility":[]}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<McpAppsResourceCsp>(
                r#"{"connectDomains":[],"connectDomains":[]}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<McpAppsResourcePermissions>(r#"{"camera":{},"camera":{}}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<McpAppsResourceMetadata>(
                r#"{"prefersBorder":false,"prefersBorder":false}"#
            )
            .is_err()
        );
    }

    #[test]
    fn apps_02_view_lifecycle_requires_initialization_before_activation() {
        assert_eq!(
            serde_json::to_value(McpAppsDisplayMode::Pip).expect("display mode serializes exactly"),
            json!("pip")
        );
        assert_eq!(
            serde_json::from_value::<McpAppsDisplayMode>(json!("fullscreen"))
                .expect("known display mode decodes"),
            McpAppsDisplayMode::Fullscreen
        );
        assert!(
            serde_json::from_value::<McpAppsDisplayMode>(json!("overlay")).is_err(),
            "only replacing a known display mode with an undeclared value rejects it"
        );

        let mut lifecycle = McpAppsViewLifecycle::default();
        assert!(!lifecycle.permits_application_traffic());
        assert_eq!(
            lifecycle.admit_initialized(),
            Err(McpAppsLifecycleError::InvalidTransition {
                from: McpAppsViewLifecycle::New,
                operation: "initialized notification",
            }),
            "only omitting the prior initialization transition rejects early activation"
        );
        assert_eq!(lifecycle, McpAppsViewLifecycle::New);

        lifecycle
            .begin_initialize()
            .expect("one initialization reservation is legal from New");
        lifecycle
            .initialization_succeeded()
            .expect("a successful initialization awaits exactly one notification");
        lifecycle
            .admit_initialized()
            .expect("the first initialized notification activates the View");
        assert!(lifecycle.permits_application_traffic());
        lifecycle
            .begin_closing()
            .expect("an active View can begin terminal teardown");
        lifecycle
            .finish_closing()
            .expect("a closing View reaches Closed exactly once");
        assert_eq!(lifecycle, McpAppsViewLifecycle::Closed);
    }

    #[test]
    fn apps_02_result_projection_rejects_one_unknown_wire_member() {
        let accepted = json!({
            "content": [{"type": "text", "text": "sunny"}],
            "isError": true
        });
        let baseline: McpAppsToolResult = serde_json::from_value(accepted.clone())
            .expect("bounded complete Apps tool result is valid");
        let mut planted = accepted.clone();
        planted["task"] = json!({"taskId": "deferred"});

        assert!(
            serde_json::from_value::<McpAppsToolResult>(planted).is_err(),
            "only adding a Tasks-shaped member rejects the complete Apps result projection"
        );
        assert_eq!(
            serde_json::to_value(&baseline).expect("baseline result re-encodes"),
            accepted,
            "the rejected Tasks-shaped member cannot mutate the complete Apps result"
        );
    }

    #[test]
    fn apps_sandbox_compilation_preserves_omission_defaults_and_host_ceiling() {
        use McpAppsCspDirective as D;
        let host = McpAppsSandboxHostPolicy::default().allow_pinned_local_sources();
        let absent = McpAppsSandboxPolicy::compile(None, &host).unwrap();
        let empty =
            McpAppsResourceMetadata::try_new(Some(McpAppsResourceCsp::default()), None, None, None)
                .unwrap();
        let present = McpAppsSandboxPolicy::compile(Some(&empty), &host).unwrap();
        assert_eq!(absent.sources(D::ConnectSrc).count(), 0);
        assert_eq!(
            present
                .sources(D::ConnectSrc)
                .map(McpAppsCspSource::as_str)
                .collect::<Vec<_>>(),
            ["'self'"]
        );
        assert_eq!(absent.sources(D::FontSrc).count(), 0);
        for policy in [&absent, &present] {
            assert!(policy.csp_header_value().contains("default-src 'none'"));
            assert!(policy.csp_header_value().contains("object-src 'none'"));
            assert!(policy.csp_header_value().contains("frame-src 'none'"));
            assert!(policy.csp_header_value().contains("base-uri 'self'"));
        }
        let deny =
            McpAppsSandboxPolicy::compile(Some(&empty), &McpAppsSandboxHostPolicy::default())
                .unwrap();
        assert!(
            McpAppsCspDirective::ALL
                .into_iter()
                .all(|directive| deny.sources(directive).count() == 0)
        );
        let removed = present
            .restrict_sources(|_, _| false)
            .restrict_sources(|_, _| true);
        assert_eq!(
            removed, deny,
            "a permissive second restriction cannot restore removed sources"
        );
    }

    #[test]
    fn apps_sandbox_sources_are_canonical_and_confined_to_their_directives() {
        use McpAppsCspDirective as D;
        let resource = McpAppsResourceMetadata::try_new(
            Some(
                McpAppsResourceCsp::try_new(
                    Some(vec!["WSS://API.EXAMPLE:443/".into()]),
                    Some(vec!["HTTPS://*.CDN.EXAMPLE:443/".into()]),
                    Some(vec!["https://frames.example".into()]),
                    Some(vec!["https://base.example:8443".into()]),
                )
                .unwrap(),
            ),
            None,
            None,
            None,
        )
        .unwrap();
        let host = McpAppsSandboxHostPolicy::default()
            .allow_pinned_local_sources()
            .allow_source(D::ConnectSrc, "wss://api.example")
            .unwrap()
            .allow_resource_source("https://*.cdn.example")
            .unwrap()
            .allow_source(D::FrameSrc, "https://frames.example")
            .unwrap()
            .allow_source(D::BaseUri, "https://base.example:8443")
            .unwrap();
        let policy = McpAppsSandboxPolicy::compile(Some(&resource), &host).unwrap();
        for directive in D::RESOURCES {
            assert!(
                policy
                    .sources(directive)
                    .any(|source| source.as_str() == "https://*.cdn.example")
            );
            assert!(
                !policy
                    .sources(directive)
                    .any(|source| source.as_str() == "wss://api.example")
            );
        }
        assert_eq!(
            policy
                .sources(D::BaseUri)
                .map(McpAppsCspSource::as_str)
                .collect::<Vec<_>>(),
            ["https://base.example:8443"]
        );
        assert_eq!(
            policy.approved_domains().resource_domains,
            Some(vec!["https://*.cdn.example".into()])
        );
        let restricted = policy.restrict_sources(|directive, source| {
            directive != D::ScriptSrc || !source.is_external()
        });
        assert_eq!(restricted.approved_domains().resource_domains, Some(vec![]));
        let none =
            McpAppsSandboxPolicy::compile(Some(&resource), &McpAppsSandboxHostPolicy::default())
                .unwrap();
        assert!(
            !none.csp_header_value().contains("example"),
            "a resource cannot grant a host-absent source"
        );
    }

    #[test]
    fn apps_sandbox_origin_admission_rejects_injection_idna_and_ambiguous_hosts() {
        use McpAppsCspDirective as D;
        for source in [
            "https://example.test/path",
            "https://example.test//",
            "https://user@example.test",
            "https://example.test?query",
            "https://example.test#fragment",
            "https://example.test:0",
            "https://example.test:65536",
            "https://example.test:",
            "https://example.test.",
            "https://xn--bcher-kva.test",
            "https://XN--BCHER-KVA.test",
            "https://bücher.test",
            "https://example.test;script-src *",
            "https://example.test\n",
            "'unsafe-eval'",
            "https://127.1",
            "https://2130706433",
            "https://0177.0.0.1",
            "https://0x7f.0.0.1",
            "https://0x",
            "https://0.0.0.0x",
            "https://*.0x",
            "https://[0:0:0:0:0:0:0:1]",
            "https://[2001:DB8::1]",
            "https://::1",
            "https://*.127.0.0.1",
            "https://*",
            "https://ex*ample.test",
            "https://*.a.*.test",
            "https://-example.test",
            "https://example-.test",
            "https://example..test",
        ] {
            assert!(
                McpAppsSandboxHostPolicy::default()
                    .allow_resource_source(source)
                    .is_err(),
                "{source}"
            );
            let resource = McpAppsResourceMetadata {
                csp: Some(McpAppsResourceCsp {
                    resource_domains: Some(vec![source.to_owned()]),
                    ..McpAppsResourceCsp::default()
                }),
                ..McpAppsResourceMetadata::default()
            };
            assert!(
                McpAppsSandboxPolicy::compile(
                    Some(&resource),
                    &McpAppsSandboxHostPolicy::default()
                )
                .is_err(),
                "an invalid resource declaration must fail even when the Host grants no sources"
            );
        }
        for source in [
            "https://127.0.0.1",
            "https://[::1]",
            "https://[2001:db8::1]:8443",
            "https://a-b.example",
        ] {
            assert!(
                McpAppsSandboxHostPolicy::default()
                    .allow_resource_source(source)
                    .is_ok(),
                "{source}"
            );
        }
        assert!(
            McpAppsSandboxHostPolicy::default()
                .allow_source(D::ConnectSrc, "https://*.example.test")
                .is_err()
        );
        assert!(
            McpAppsSandboxHostPolicy::default()
                .allow_source(D::FrameSrc, "wss://example.test")
                .is_err()
        );
        assert!(
            McpAppsSandboxHostPolicy::default()
                .allow_source(D::ObjectSrc, "https://example.test")
                .is_err()
        );
        for source in ["http://localhost", "http://127.0.0.1", "http://[::1]:8080"] {
            assert!(
                McpAppsSandboxHostPolicy::default()
                    .allow_resource_source(source)
                    .is_err()
            );
            assert!(
                McpAppsSandboxHostPolicy::new(McpAppsCspMode::LocalDevelopment)
                    .allow_resource_source(source)
                    .is_ok()
            );
        }
        for source in [
            "http://localhost.example",
            "http://127.0.0.2",
            "http://*.localhost",
        ] {
            assert!(
                McpAppsSandboxHostPolicy::new(McpAppsCspMode::LocalDevelopment)
                    .allow_resource_source(source)
                    .is_err()
            );
        }
        assert!(
            McpAppsSandboxHostPolicy::new(McpAppsCspMode::LocalDevelopment)
                .allow_source(D::ConnectSrc, "ws://localhost:8080")
                .is_ok()
        );
        assert!(
            McpAppsSandboxHostPolicy::new(McpAppsCspMode::LocalDevelopment)
                .allow_resource_source("ws://localhost")
                .is_err()
        );
        let excessive = McpAppsResourceMetadata {
            csp: Some(McpAppsResourceCsp {
                resource_domains: Some(vec![
                    "https://example.test".to_owned();
                    MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE + 1
                ]),
                ..McpAppsResourceCsp::default()
            }),
            ..McpAppsResourceMetadata::default()
        };
        assert_eq!(
            McpAppsSandboxPolicy::compile(Some(&excessive), &McpAppsSandboxHostPolicy::default()),
            Err(McpAppsSandboxPolicyError::TooManySources)
        );
        let mut host = McpAppsSandboxHostPolicy::default().allow_pinned_local_sources();
        for index in 0..MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE {
            host = host
                .allow_resource_source(&format!("https://source-{index}.example"))
                .unwrap();
        }
        let baseline = host.clone();
        assert_eq!(
            host.clone()
                .allow_resource_source("https://one-more.example"),
            Err(McpAppsSandboxPolicyError::TooManySources)
        );
        assert_eq!(
            host.clone()
                .allow_resource_source("https://SOURCE-0.EXAMPLE:443/")
                .unwrap(),
            baseline,
            "a canonical duplicate consumes no extra source slot"
        );
        assert_eq!(
            host, baseline,
            "denial cannot mutate a previously compiled Host ceiling"
        );
    }

    #[test]
    fn apps_sandbox_permissions_require_every_host_layer_and_do_not_resurrect_listing() {
        use McpAppsSandboxPermission as P;
        for permission in P::ALL {
            for bits in 0_u8..32 {
                let included = |bit: u32| {
                    if bits & (1_u8 << bit) != 0 {
                        vec![permission]
                    } else {
                        vec![]
                    }
                };
                let marker = McpAppsResourcePermission::default();
                let mut requested = McpAppsResourcePermissions::default();
                if bits & 1 != 0 {
                    match permission {
                        P::Camera => requested.camera = Some(marker),
                        P::Microphone => requested.microphone = Some(marker),
                        P::Geolocation => requested.geolocation = Some(marker),
                        P::ClipboardWrite => requested.clipboard_write = Some(marker),
                    }
                }
                let metadata =
                    McpAppsResourceMetadata::try_new(None, Some(requested), None, None).unwrap();
                let host = McpAppsSandboxHostPolicy::default().with_permissions(
                    included(1),
                    included(2),
                    included(3),
                    included(4),
                );
                let policy = McpAppsSandboxPolicy::compile(Some(&metadata), &host).unwrap();
                let expected = bits & 7 == 7 && (bits & 8 == 0 || bits & 16 != 0);
                assert_eq!(
                    policy.permission_granted(permission),
                    expected,
                    "{permission:?} bits={bits}"
                );
                let wire = serde_json::to_value(policy.granted_permissions()).unwrap();
                let key = if permission == P::ClipboardWrite {
                    "clipboardWrite"
                } else {
                    permission.as_str()
                };
                assert_eq!(wire.get(key).is_some(), expected);
                assert!(
                    !policy
                        .restrict_permissions(|_| false)
                        .restrict_permissions(|_| true)
                        .permission_granted(permission)
                );
            }
        }
        let binding = apps_read_binding();
        let mut listed = apps_read_listing();
        listed.meta =
            Some(serde_json::from_value(json!({"ui":{"permissions":{"camera":{}}}})).unwrap());
        let mut item = apps_read_item();
        item["_meta"] = json!({"ui":{}});
        let read = apps_read_result(vec![item]);
        let host =
            McpAppsSandboxHostPolicy::default().with_permissions([P::Camera], [P::Camera], [], []);
        let selected = binding.resolve_read_result(&read, Some(&listed)).unwrap();
        assert!(
            !selected
                .compile_sandbox_policy(&host)
                .unwrap()
                .permission_granted(P::Camera),
            "present-empty read metadata cannot resurrect listing permission requests"
        );
    }

    #[test]
    fn sampling_capability_round_trips_tools_and_context() {
        // Official MCP 2026-07-28 ClientCapabilities.sampling carries optional
        // `context` and `tools` objects; decoding must not drop them.
        let wire = json!({"sampling": {"tools": {}, "context": {"note": "kept"}}});
        let capabilities: ClientCapabilities =
            serde_json::from_value(wire.clone()).expect("decode official sampling capability");
        let sampling = capabilities.sampling.as_ref().expect("sampling present");
        assert!(sampling.tools.is_some());
        assert_eq!(
            sampling
                .context
                .as_ref()
                .and_then(|context| context.get("note")),
            Some(&json!("kept"))
        );
        assert_eq!(
            serde_json::to_value(&capabilities).expect("encode"),
            wire,
            "a decoded sampling capability must re-encode without loss"
        );

        // Near-identical negative: plain sampling stays exactly `{}`; the new
        // members never appear unless declared.
        let plain = ClientCapabilities {
            sampling: Some(SamplingCapability::default()),
            ..ClientCapabilities::default()
        };
        assert_eq!(
            serde_json::to_value(&plain).expect("encode")["sampling"],
            json!({})
        );
        let builder = SamplingCapability::default().with_tools().with_context();
        assert_eq!(
            serde_json::to_value(&builder).expect("encode"),
            json!({"tools": {}, "context": {}})
        );
    }
}
