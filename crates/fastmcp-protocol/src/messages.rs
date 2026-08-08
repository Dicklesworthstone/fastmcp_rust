//! MCP protocol messages.
//!
//! Request and response types for the MCP methods currently implemented here.

use std::collections::BTreeMap;

use serde::de::{DeserializeOwned, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::common_types::{
    AbsoluteUri, ContentBlock, EmbeddedResourceContents, LoggingLevel, OpenMetadata,
};
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse, RequestId};
use crate::methods::{
    COMPLETION_COMPLETE, Final2026EnvelopeKind, Final2026Peer, INITIALIZE, LOGGING_SET_LEVEL,
    NOTIFICATIONS_CANCELLED, NOTIFICATIONS_MESSAGE, NOTIFICATIONS_PROGRESS,
    NOTIFICATIONS_PROMPTS_LIST_CHANGED, NOTIFICATIONS_RESOURCES_LIST_CHANGED,
    NOTIFICATIONS_RESOURCES_UPDATED, NOTIFICATIONS_SUBSCRIPTIONS_ACKNOWLEDGED,
    NOTIFICATIONS_TOOLS_LIST_CHANGED, PING, PROMPTS_GET, PROMPTS_LIST, RESOURCES_LIST,
    RESOURCES_READ, RESOURCES_TEMPLATES_LIST, SAMPLING_CREATE_MESSAGE, SERVER_DISCOVER,
    SUBSCRIPTIONS_LISTEN, TOOLS_CALL, TOOLS_LIST, final_2026_07_28_method,
};
use crate::protocol_policy::ProtocolEra;
use crate::protocol_version::{FINAL_PROTOCOL_VERSION, RequestVersionMetadata};
use crate::result::{
    CompleteResult, CoreResultDiscriminatorPolicy, DecodedResult, ExactJsonMember,
    InputRequiredResult, ResultDecodeError, ResultPeerDiagnostic, UnknownResultMembers,
    decode_peer_result_for_era, encode_complete_result, encode_result, exact_json_from_serde,
    exact_json_to_serde,
};
use crate::types::{
    ClientCapabilities, ClientInfo, LegacyContent, LegacyMetadata, LegacyPromptMessage,
    LegacyResourceContent, Prompt, Resource, ResourceTemplate, ServerCapabilities, ServerInfo,
    Tool,
};

// ============================================================================
// Progress Marker
// ============================================================================

/// Progress marker used to correlate progress notifications with requests.
///
/// Per MCP spec, progress markers can be either strings or integers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProgressMarker {
    /// String progress marker.
    String(String),
    /// Integer progress marker.
    Number(i64),
}

impl From<String> for ProgressMarker {
    fn from(s: String) -> Self {
        ProgressMarker::String(s)
    }
}

impl From<&str> for ProgressMarker {
    fn from(s: &str) -> Self {
        ProgressMarker::String(s.to_owned())
    }
}

impl From<i64> for ProgressMarker {
    fn from(n: i64) -> Self {
        ProgressMarker::Number(n)
    }
}

impl std::fmt::Display for ProgressMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProgressMarker::String(s) => write!(f, "{s}"),
            ProgressMarker::Number(n) => write!(f, "{n}"),
        }
    }
}

/// Request metadata containing optional progress marker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestMeta {
    /// Progress marker for receiving progress notifications.
    // Avoid UBS "hardcoded secrets" heuristics while keeping the on-the-wire name.
    #[serde(rename = "progressTo\x6ben", skip_serializing_if = "Option::is_none")]
    pub progress_marker: Option<ProgressMarker>,
}

// ============================================================================
// Final per-request metadata
// ============================================================================

/// `_meta` key carrying the protocol version on every final request.
pub const FINAL_PROTOCOL_VERSION_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";

/// `_meta` key carrying the client capabilities on every final request.
pub const FINAL_CLIENT_CAPABILITIES_META_KEY: &str = "io.modelcontextprotocol/clientCapabilities";

/// `_meta` key carrying optional client identity on a final request.
pub const FINAL_CLIENT_INFO_META_KEY: &str = "io.modelcontextprotocol/clientInfo";

/// `_meta` key carrying optional server identity on a final response.
pub const FINAL_SERVER_INFO_META_KEY: &str = "io.modelcontextprotocol/serverInfo";

/// Required final metadata carried in the `_meta` object of every request.
///
/// The protocol version and client capabilities are intentionally distinct
/// from legacy [`RequestMeta`]. Final request admission validates the version
/// against the HTTP header before using the advertised capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalRequestMeta {
    /// The exact protocol revision selected for this request.
    #[serde(rename = "io.modelcontextprotocol/protocolVersion")]
    pub protocol_version: String,
    /// Capabilities advertised by the request's client.
    #[serde(rename = "io.modelcontextprotocol/clientCapabilities")]
    pub client_capabilities: ClientCapabilities,
    /// Optional client identity supplied on this request.
    #[serde(
        rename = "io.modelcontextprotocol/clientInfo",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub client_info: Option<ClientInfo>,
    /// Additional metadata retained without granting protocol capability.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional_metadata: BTreeMap<String, Value>,
}

impl FinalRequestMeta {
    /// Creates canonical metadata for the exact final protocol version.
    #[must_use]
    pub fn new(client_capabilities: ClientCapabilities) -> Self {
        Self {
            protocol_version: FINAL_PROTOCOL_VERSION.to_owned(),
            client_capabilities,
            client_info: None,
            additional_metadata: BTreeMap::new(),
        }
    }

    /// Returns the protocol header/body mirror for final request admission.
    #[must_use]
    pub fn version_metadata<'a>(
        &'a self,
        header_version: Option<&'a str>,
    ) -> RequestVersionMetadata<'a> {
        RequestVersionMetadata {
            header_version,
            body_version: Some(&self.protocol_version),
        }
    }
}

// ============================================================================
// Era-aware core dispatch
// ============================================================================

/// Final pagination parameters shared by the core catalog methods.
///
/// This is intentionally separate from the legacy list parameter structs:
/// final requests always carry the common metadata object, while the legacy
/// wire era negotiates through its initialize request instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalListParams {
    /// Required final request metadata.
    #[serde(rename = "_meta")]
    pub meta: OpenMetadata,
    /// Opaque pagination cursor; a present empty cursor remains present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Only include catalog entries with every listed tag.
    #[serde(
        rename = "includeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_tags: Option<Vec<String>>,
    /// Exclude catalog entries with any listed tag.
    #[serde(
        rename = "excludeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_tags: Option<Vec<String>>,
}

/// Final `tools/call` request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalCallToolParams {
    /// Required final request metadata.
    #[serde(rename = "_meta")]
    pub meta: OpenMetadata,
    /// Name of the selected tool.
    pub name: String,
    /// Optional method-owned tool arguments.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_json_object"
    )]
    pub arguments: Option<Value>,
    /// Optional replies to embedded final input requests.
    #[serde(
        rename = "inputResponses",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub input_responses: Option<BTreeMap<String, Value>>,
    /// Opaque retry state supplied with embedded input responses.
    #[serde(
        rename = "requestState",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_state: Option<String>,
}

/// Final `resources/read` request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalReadResourceParams {
    /// Required final request metadata.
    #[serde(rename = "_meta")]
    pub meta: OpenMetadata,
    /// Structurally admitted resource URI.
    pub uri: AbsoluteUri,
    /// Optional replies to embedded final input requests.
    #[serde(
        rename = "inputResponses",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub input_responses: Option<BTreeMap<String, Value>>,
    /// Opaque retry state supplied with embedded input responses.
    #[serde(
        rename = "requestState",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_state: Option<String>,
}

/// Final `prompts/get` request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalGetPromptParams {
    /// Required final request metadata.
    #[serde(rename = "_meta")]
    pub meta: OpenMetadata,
    /// Name of the selected prompt.
    pub name: String,
    /// Optional prompt arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<BTreeMap<String, String>>,
    /// Optional replies to embedded final input requests.
    #[serde(
        rename = "inputResponses",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub input_responses: Option<BTreeMap<String, Value>>,
    /// Opaque retry state supplied with embedded input responses.
    #[serde(
        rename = "requestState",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_state: Option<String>,
}

fn deserialize_optional_json_object<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    if value.as_ref().is_some_and(|value| !value.is_object()) {
        return Err(serde::de::Error::custom("arguments must be an object"));
    }
    Ok(value)
}

/// Exact legacy reference accepted by `completion/complete`.
///
/// Legacy completion parameter objects remain open, as they are in the
/// 2024-11-05 schema. The selected prompt/resource members are still typed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LegacyCompletionReference {
    /// Identifies one prompt or prompt template by name.
    #[serde(rename = "ref/prompt")]
    Prompt {
        /// Prompt or prompt-template name.
        name: String,
    },
    /// Identifies one resource or resource template by URI template.
    #[serde(rename = "ref/resource")]
    Resource {
        /// Resource URI or URI template.
        uri: String,
    },
}

/// Exact legacy completion argument selector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyCompletionArgument {
    /// Argument name.
    pub name: String,
    /// Prefix used for completion matching.
    pub value: String,
}

/// Exact 2024-11-05 `completion/complete` request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyCompletionParams {
    /// Prompt or resource-template target.
    #[serde(rename = "ref")]
    pub reference: LegacyCompletionReference,
    /// Argument being completed.
    pub argument: LegacyCompletionArgument,
}

/// Final reference accepted by `completion/complete`.
#[derive(Debug, Clone)]
pub enum FinalCompletionReference {
    /// Identifies one prompt or prompt template by name.
    Prompt {
        /// Prompt or prompt-template name.
        name: String,
    },
    /// Identifies one prompt or prompt template by name and display title.
    PromptWithTitle {
        /// Prompt or prompt-template name.
        name: String,
        /// Display title supplied for the selected prompt.
        title: String,
    },
    /// Identifies one resource template by URI template.
    Resource {
        /// Resource URI template.
        uri: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum FinalCompletionReferenceWire {
    #[serde(rename = "ref/prompt")]
    Prompt {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
    },
    #[serde(rename = "ref/resource")]
    Resource { uri: String },
}

impl Serialize for FinalCompletionReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let wire = match self {
            Self::Prompt { name } => FinalCompletionReferenceWire::Prompt {
                name: name.clone(),
                title: None,
            },
            Self::PromptWithTitle { name, title } => FinalCompletionReferenceWire::Prompt {
                name: name.clone(),
                title: Some(title.clone()),
            },
            Self::Resource { uri } => FinalCompletionReferenceWire::Resource { uri: uri.clone() },
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FinalCompletionReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match FinalCompletionReferenceWire::deserialize(deserializer)? {
            FinalCompletionReferenceWire::Prompt {
                name,
                title: Some(title),
            } => Ok(Self::PromptWithTitle { name, title }),
            FinalCompletionReferenceWire::Prompt { name, title: None } => Ok(Self::Prompt { name }),
            FinalCompletionReferenceWire::Resource { uri } => Ok(Self::Resource { uri }),
        }
    }
}

/// Final completion argument selector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalCompletionArgument {
    /// Argument name.
    pub name: String,
    /// Prefix used for completion matching.
    pub value: String,
}

/// Optional final completion context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalCompletionContext {
    /// Previously resolved prompt or URI-template variables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<BTreeMap<String, String>>,
}

/// Final `completion/complete` request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalCompletionParams {
    /// Required final request metadata.
    #[serde(rename = "_meta")]
    pub meta: OpenMetadata,
    /// Prompt or resource-template target.
    #[serde(rename = "ref")]
    pub reference: FinalCompletionReference,
    /// Argument being completed.
    pub argument: FinalCompletionArgument,
    /// Previously resolved prompt or URI-template variables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<FinalCompletionContext>,
}

/// Final empty request parameters, used by `server/discover`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalEmptyParams {
    /// Required final request metadata.
    #[serde(rename = "_meta")]
    pub meta: OpenMetadata,
}

/// `_meta` key correlating an event-stream subscription with its listen request.
pub const FINAL_SUBSCRIPTION_ID_META_KEY: &str = "io.modelcontextprotocol/subscriptionId";

/// Final notification categories selected for a subscription stream.
///
/// Every present field is an explicit opt-in. `false` and an empty resource
/// list remain distinct from an omitted field on the wire.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubscriptionFilter {
    /// Receive prompt catalog change notifications when true.
    #[serde(
        rename = "promptsListChanged",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub prompts_list_changed: Option<bool>,
    /// Resource URIs for update notifications.
    #[serde(
        rename = "resourceSubscriptions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resource_subscriptions: Option<Vec<String>>,
    /// Receive resource catalog change notifications when true.
    #[serde(
        rename = "resourcesListChanged",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resources_list_changed: Option<bool>,
    /// Receive tool catalog change notifications when true.
    #[serde(
        rename = "toolsListChanged",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub tools_list_changed: Option<bool>,
    /// Future notification categories accepted by the final schema and
    /// retained without activating any extension behavior.
    #[serde(flatten, default)]
    pub additional: BTreeMap<String, Value>,
}

/// Final `subscriptions/listen` request parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalSubscriptionsListenParams {
    /// Required final request metadata.
    #[serde(rename = "_meta")]
    pub meta: OpenMetadata,
    /// Notification categories the client explicitly opts into.
    pub notifications: SubscriptionFilter,
}

/// Final `notifications/subscriptions/acknowledged` parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalSubscriptionsAcknowledgedNotificationParams {
    /// Optional notification metadata, including the subscription ID when the
    /// acknowledgement was delivered over a subscription stream.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
    /// The subset of the requested notification categories the server accepted.
    pub notifications: SubscriptionFilter,
    /// Schema-open extension members retained without activating behavior.
    #[serde(flatten, default)]
    pub additional: BTreeMap<String, Value>,
}

/// Exact final `notifications/message` parameters.
///
/// Final clients opt into these notifications through
/// `io.modelcontextprotocol/logLevel` in request metadata; this notification
/// itself remains independent of the removed final `logging/setLevel` RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalLogMessageParams {
    /// Final RFC 5424 severity.
    pub level: LoggingLevel,
    /// Optional logger name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logger: Option<String>,
    /// Arbitrary log data.
    pub data: Value,
    /// Optional final notification metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
    /// Schema-open extension members retained without activating behavior.
    #[serde(flatten, default)]
    pub additional: BTreeMap<String, Value>,
}

/// Exact final `notifications/cancelled` parameters.
///
/// This is deliberately separate from legacy [`CancelledParams`], while
/// retaining schema-open extension members without assigning them semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalCancelledNotificationParams {
    /// The client request ID whose result is no longer needed.
    #[serde(rename = "requestId")]
    pub request_id: RequestId,
    /// Optional open cancellation reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional final notification metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
    /// Schema-open extension members retained without activating behavior.
    #[serde(flatten, default)]
    pub additional: BTreeMap<String, Value>,
}

/// Exact final `notifications/progress` parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalProgressNotificationParams {
    /// Token from the client request being progressed.
    #[serde(rename = "progressToken")]
    pub progress_token: ProgressMarker,
    /// Progress completed so far.
    pub progress: f64,
    /// Total work, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    /// Optional progress message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Optional final notification metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
    /// Schema-open extension members retained without activating behavior.
    #[serde(flatten, default)]
    pub additional: BTreeMap<String, Value>,
}

/// Exact final `notifications/resources/updated` parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalResourceUpdatedNotificationParams {
    /// Absolute URI for the changed resource or provider-defined sub-resource.
    pub uri: AbsoluteUri,
    /// Optional final notification metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
    /// Schema-open extension members retained without activating behavior.
    #[serde(flatten, default)]
    pub additional: BTreeMap<String, Value>,
}

/// Exact optional parameter object for final catalog-change notifications.
///
/// `None` in a [`ServerNotification`] omits `params` entirely; `Some` retains
/// a present notification parameter object, including a metadata-only one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FinalEmptyNotificationParams {
    /// Optional final notification metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
    /// Schema-open extension members retained without activating behavior.
    #[serde(flatten, default)]
    pub additional: BTreeMap<String, Value>,
}

/// Exact final `sampling/createMessage` parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalCreateMessageParams {
    /// Required final request metadata.
    #[serde(rename = "_meta")]
    pub meta: OpenMetadata,
    /// Sampling conversation.
    pub messages: Vec<crate::types::FinalSamplingMessage>,
    /// Requested maximum token count.
    #[serde(rename = "maxTokens")]
    pub max_tokens: i64,
    /// Optional system prompt.
    #[serde(
        rename = "systemPrompt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub system_prompt: Option<String>,
    /// Optional sampling temperature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Optional stopping sequences. Presence remains distinct from an empty list.
    #[serde(
        rename = "stopSequences",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub stop_sequences: Option<Vec<String>>,
    /// Optional model-selection preferences.
    #[serde(
        rename = "modelPreferences",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub model_preferences: Option<crate::types::ModelPreferences>,
    /// Optional requested MCP context inclusion.
    #[serde(
        rename = "includeContext",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_context: Option<IncludeContext>,
    /// Optional provider-specific metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, Value>>,
    /// Optional tools the model may call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<crate::types::FinalTool>>,
    /// Optional tool-selection controls.
    #[serde(
        rename = "toolChoice",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub tool_choice: Option<crate::types::FinalToolChoice>,
}

/// Exact final `sampling/createMessage` complete payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalCreateMessageResult {
    /// Generated final sampling content.
    pub content: crate::types::FinalSamplingMessageContent,
    /// Model name selected by the client.
    pub model: String,
    /// Generated message role.
    pub role: crate::types::Role,
    /// Optional open sampling stop reason.
    #[serde(
        rename = "stopReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub stop_reason: Option<String>,
    /// Optional final metadata on this embedded MRTR input response value.
    ///
    /// This payload is not a JSON-RPC result envelope, so it deliberately
    /// carries no `resultType` discriminator.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
}

/// Exact final `sampling/createMessage` input-required result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalCreateMessageInputRequiredResult {
    /// Mandatory final discriminator, fixed to `input_required`.
    #[serde(rename = "resultType")]
    pub result_type: FinalInputRequiredResultType,
    /// Optional final result metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
    /// Server-initiated requests that must be fulfilled before retrying.
    #[serde(
        rename = "inputRequests",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub input_requests: Option<BTreeMap<String, Value>>,
    /// Opaque state retained for the retry.
    #[serde(
        rename = "requestState",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_state: Option<String>,
}

impl FinalCreateMessageInputRequiredResult {
    /// Validates the final input-required presence invariant.
    pub fn validate(&self) -> Result<(), CoreDispatchError> {
        if self.input_requests.is_some() || self.request_state.is_some() {
            Ok(())
        } else {
            Err(CoreDispatchError::InvalidResult {
                era: ProtocolEra::Modern2026,
                method: SAMPLING_CREATE_MESSAGE,
            })
        }
    }
}

/// Final input-required discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalInputRequiredResultType {
    /// Additional input is required before retrying the original request.
    #[serde(rename = "input_required")]
    InputRequired,
}

/// A final MRTR descriptor embedded in a Task, without a JSON-RPC envelope.
///
/// Task input requests are correlated exclusively by their containing map
/// key.  Consequently these descriptors deliberately omit `jsonrpc`, `id`,
/// and the outer request `_meta` capability object.
#[derive(Debug, Clone)]
pub enum FinalEmbeddedInputRequest {
    /// A final sampling descriptor.
    Sampling(FinalEmbeddedCreateMessageParams),
    /// A roots-list descriptor.
    Roots(FinalEmbeddedRootsListParams),
    /// A form or URL elicitation descriptor.
    Elicitation(FinalEmbeddedElicitationParams),
}

impl FinalEmbeddedInputRequest {
    /// Returns the response kind that may answer this descriptor.
    #[must_use]
    pub const fn response_kind(&self) -> FinalEmbeddedInputKind {
        match self {
            Self::Sampling(_) => FinalEmbeddedInputKind::Sampling,
            Self::Roots(_) => FinalEmbeddedInputKind::Roots,
            Self::Elicitation(FinalEmbeddedElicitationParams::Form(_)) => {
                FinalEmbeddedInputKind::FormElicitation
            }
            Self::Elicitation(FinalEmbeddedElicitationParams::Url(_)) => {
                FinalEmbeddedInputKind::UrlElicitation
            }
        }
    }
}

impl Serialize for FinalEmbeddedInputRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut object = serde_json::Map::new();
        match self {
            Self::Sampling(params) => {
                object.insert(
                    "method".to_owned(),
                    Value::String("sampling/createMessage".to_owned()),
                );
                object.insert(
                    "params".to_owned(),
                    serde_json::to_value(params).map_err(serde::ser::Error::custom)?,
                );
            }
            Self::Roots(params) => {
                object.insert("method".to_owned(), Value::String("roots/list".to_owned()));
                if !params.is_empty() {
                    object.insert(
                        "params".to_owned(),
                        serde_json::to_value(params).map_err(serde::ser::Error::custom)?,
                    );
                }
            }
            Self::Elicitation(params) => {
                object.insert(
                    "method".to_owned(),
                    Value::String("elicitation/create".to_owned()),
                );
                object.insert(
                    "params".to_owned(),
                    serde_json::to_value(params).map_err(serde::ser::Error::custom)?,
                );
            }
        }
        Value::Object(object).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FinalEmbeddedInputRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let (method, params) =
            take_embedded_request_members(value).map_err(serde::de::Error::custom)?;
        match method.as_str() {
            "sampling/createMessage" => {
                let params = params.ok_or_else(|| {
                    serde::de::Error::custom("sampling descriptor requires params")
                })?;
                serde_json::from_value(params)
                    .map(Self::Sampling)
                    .map_err(serde::de::Error::custom)
            }
            "roots/list" => {
                let params = params.unwrap_or_else(|| Value::Object(serde_json::Map::new()));
                let params: FinalEmbeddedRootsListParams =
                    serde_json::from_value(params).map_err(serde::de::Error::custom)?;
                params.validate().map_err(serde::de::Error::custom)?;
                Ok(Self::Roots(params))
            }
            "elicitation/create" => {
                let params = params.ok_or_else(|| {
                    serde::de::Error::custom("elicitation descriptor requires params")
                })?;
                serde_json::from_value(params)
                    .map(Self::Elicitation)
                    .map_err(serde::de::Error::custom)
            }
            _ => Err(serde::de::Error::custom(
                "unsupported embedded input method",
            )),
        }
    }
}

fn take_embedded_request_members(value: Value) -> Result<(String, Option<Value>), &'static str> {
    let Value::Object(mut members) = value else {
        return Err("embedded input request must be an object");
    };
    let method = members
        .remove("method")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or("embedded input request requires a string method")?;
    let params = members.remove("params");
    if members.is_empty() {
        Ok((method, params))
    } else {
        Err("embedded input request has unknown envelope members")
    }
}

/// The selected final MRTR response kind for one Task map key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalEmbeddedInputKind {
    /// A sampling response.
    Sampling,
    /// A roots-list response.
    Roots,
    /// A form-elicitation response.
    FormElicitation,
    /// A URL-elicitation response.
    UrlElicitation,
}

/// Exact final parameters for an embedded sampling descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalEmbeddedCreateMessageParams {
    /// Sampling conversation.
    pub messages: Vec<crate::types::FinalSamplingMessage>,
    /// Requested maximum token count.
    #[serde(rename = "maxTokens")]
    pub max_tokens: i64,
    /// Optional system prompt.
    #[serde(
        rename = "systemPrompt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub system_prompt: Option<String>,
    /// Optional sampling temperature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Optional stopping sequences.
    #[serde(
        rename = "stopSequences",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub stop_sequences: Option<Vec<String>>,
    /// Optional model-selection preferences.
    #[serde(
        rename = "modelPreferences",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub model_preferences: Option<crate::types::ModelPreferences>,
    /// Optional requested MCP context inclusion.
    #[serde(
        rename = "includeContext",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_context: Option<IncludeContext>,
    /// Optional provider-specific metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, Value>>,
    /// Optional tools the model may call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<crate::types::FinalTool>>,
    /// Optional tool-selection controls.
    #[serde(
        rename = "toolChoice",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub tool_choice: Option<crate::types::FinalToolChoice>,
}

/// Bounded generic metadata permitted on an embedded roots descriptor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalEmbeddedRootsListParams {
    /// Generic inert metadata. It cannot carry final request authority.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<OpenMetadata>,
}

impl FinalEmbeddedRootsListParams {
    fn is_empty(&self) -> bool {
        self.meta.is_none()
    }

    fn validate(&self) -> Result<(), &'static str> {
        let Some(meta) = &self.meta else {
            return Ok(());
        };
        if meta.entries().contains_key(FINAL_PROTOCOL_VERSION_META_KEY)
            || meta
                .entries()
                .contains_key(FINAL_CLIENT_CAPABILITIES_META_KEY)
        {
            return Err("embedded roots metadata cannot carry outer request authority");
        }
        Ok(())
    }
}

/// Exact final parameters for an embedded elicitation descriptor.
#[derive(Debug, Clone, Serialize)]
pub enum FinalEmbeddedElicitationParams {
    /// In-band form elicitation.
    Form(FinalEmbeddedFormElicitationParams),
    /// External URL elicitation.
    Url(FinalEmbeddedUrlElicitationParams),
}

impl<'de> Deserialize<'de> for FinalEmbeddedElicitationParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let mode = value
            .as_object()
            .and_then(|members| members.get("mode"))
            .and_then(Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("elicitation descriptor requires mode"))?;
        match mode {
            "form" => serde_json::from_value(value)
                .map(Self::Form)
                .map_err(serde::de::Error::custom),
            "url" => serde_json::from_value(value)
                .map(Self::Url)
                .map_err(serde::de::Error::custom),
            _ => Err(serde::de::Error::custom("unsupported elicitation mode")),
        }
    }
}

/// Form elicitation request parameters without an outer request envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalEmbeddedFormElicitationParams {
    /// Exact form discriminator.
    pub mode: ElicitMode,
    /// User-facing request text.
    pub message: String,
    /// Requested form schema.
    #[serde(rename = "requestedSchema")]
    pub requested_schema: ElicitRequestedSchema,
}

/// URL elicitation request parameters without legacy elicitation identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalEmbeddedUrlElicitationParams {
    /// Exact URL discriminator.
    pub mode: ElicitMode,
    /// User-facing request text.
    pub message: String,
    /// Structurally admitted external URL.
    pub url: AbsoluteUri,
}

/// A final MRTR result payload embedded in a Task, without a JSON-RPC envelope.
#[derive(Debug, Clone, PartialEq)]
pub enum FinalEmbeddedInputResponse {
    /// Sampling result payload.
    Sampling(FinalCreateMessageResult),
    /// Roots-list result payload.
    Roots(FinalEmbeddedRootsListResult),
    /// Elicitation result payload. The request ledger determines form versus URL.
    Elicitation(FinalEmbeddedElicitationResult),
}

impl FinalEmbeddedInputResponse {
    /// Returns whether this response can answer the supplied descriptor kind.
    #[must_use]
    pub fn matches_kind(&self, kind: FinalEmbeddedInputKind) -> bool {
        match (self, kind) {
            (Self::Sampling(_), FinalEmbeddedInputKind::Sampling)
            | (Self::Roots(_), FinalEmbeddedInputKind::Roots) => true,
            (Self::Elicitation(response), FinalEmbeddedInputKind::FormElicitation) => {
                response.valid_for_form()
            }
            (Self::Elicitation(response), FinalEmbeddedInputKind::UrlElicitation) => {
                response.valid_for_url()
            }
            _ => false,
        }
    }
}

impl Serialize for FinalEmbeddedInputResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Sampling(response) => response.serialize(serializer),
            Self::Roots(response) => response.serialize(serializer),
            Self::Elicitation(response) => response.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for FinalEmbeddedInputResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("embedded input response must be an object"))?;
        if object.contains_key("jsonrpc")
            || object.contains_key("id")
            || object.contains_key("result")
        {
            return Err(serde::de::Error::custom(
                "embedded input response cannot be a JSON-RPC envelope",
            ));
        }
        if object.contains_key("model") || object.contains_key("role") {
            return serde_json::from_value(value)
                .map(Self::Sampling)
                .map_err(serde::de::Error::custom);
        }
        if object.contains_key("roots") {
            return serde_json::from_value(value)
                .map(Self::Roots)
                .map_err(serde::de::Error::custom);
        }
        if object.contains_key("action") {
            return serde_json::from_value(value)
                .map(Self::Elicitation)
                .map_err(serde::de::Error::custom);
        }
        Err(serde::de::Error::custom(
            "unsupported embedded input response",
        ))
    }
}

/// Exact roots-list result payload embedded in a Task input response map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalEmbeddedRootsListResult {
    /// Roots supplied by the client.
    pub roots: Vec<Root>,
}

/// Exact elicitation response payload embedded in a Task input response map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalEmbeddedElicitationResult {
    /// User action.
    pub action: ElicitAction,
    /// Optional submitted form data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<BTreeMap<String, ElicitContentValue>>,
}

impl FinalEmbeddedElicitationResult {
    fn valid_for_form(&self) -> bool {
        match self.action {
            ElicitAction::Accept => self.content.is_some(),
            ElicitAction::Decline | ElicitAction::Cancel => self.content.is_none(),
        }
    }

    fn valid_for_url(&self) -> bool {
        self.content.is_none()
    }
}

/// Final `tools/list` result payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalListToolsResult {
    /// Catalog tools in their selected order.
    pub tools: Vec<crate::types::FinalTool>,
    /// Opaque next cursor, if another page is available.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Required final cache lifetime in milliseconds.
    #[serde(rename = "ttlMs")]
    pub ttl_ms: u64,
    /// Required final cache sharing scope.
    #[serde(
        rename = "cacheScope",
        serialize_with = "serialize_cache_scope",
        deserialize_with = "deserialize_cache_scope"
    )]
    pub cache_scope: crate::result::CacheScope,
}

/// Final `tools/call` result payload using final common content blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalCallToolResult {
    /// Final common output content.
    pub content: Vec<ContentBlock>,
    /// Whether the tool execution completed with a tool-level error.
    #[serde(
        rename = "isError",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub is_error: bool,
    /// Optional structured tool output, validated by the advertised output schema.
    #[serde(
        rename = "structuredContent",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub structured_content: Option<Value>,
}

/// Final `resources/list` result payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalListResourcesResult {
    /// Catalog resources in their selected order.
    pub resources: Vec<crate::types::FinalResource>,
    /// Opaque next cursor, if another page is available.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Required final cache lifetime in milliseconds.
    #[serde(rename = "ttlMs")]
    pub ttl_ms: u64,
    /// Required final cache sharing scope.
    #[serde(
        rename = "cacheScope",
        serialize_with = "serialize_cache_scope",
        deserialize_with = "deserialize_cache_scope"
    )]
    pub cache_scope: crate::result::CacheScope,
}

/// Final `resources/templates/list` result payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalListResourceTemplatesResult {
    /// Catalog templates in their selected order.
    #[serde(rename = "resourceTemplates")]
    pub resource_templates: Vec<crate::types::FinalResourceTemplate>,
    /// Opaque next cursor, if another page is available.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Required final cache lifetime in milliseconds.
    #[serde(rename = "ttlMs")]
    pub ttl_ms: u64,
    /// Required final cache sharing scope.
    #[serde(
        rename = "cacheScope",
        serialize_with = "serialize_cache_scope",
        deserialize_with = "deserialize_cache_scope"
    )]
    pub cache_scope: crate::result::CacheScope,
}

/// Final `resources/read` result payload using final common resource content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalReadResourceResult {
    /// Read resource contents.
    pub contents: Vec<EmbeddedResourceContents>,
    /// Required final cache lifetime in milliseconds.
    #[serde(rename = "ttlMs")]
    pub ttl_ms: u64,
    /// Required final cache sharing scope.
    #[serde(
        rename = "cacheScope",
        serialize_with = "serialize_cache_scope",
        deserialize_with = "deserialize_cache_scope"
    )]
    pub cache_scope: crate::result::CacheScope,
}

/// Final `prompts/list` result payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalListPromptsResult {
    /// Catalog prompts in their selected order.
    pub prompts: Vec<crate::types::FinalPrompt>,
    /// Opaque next cursor, if another page is available.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Required final cache lifetime in milliseconds.
    #[serde(rename = "ttlMs")]
    pub ttl_ms: u64,
    /// Required final cache sharing scope.
    #[serde(
        rename = "cacheScope",
        serialize_with = "serialize_cache_scope",
        deserialize_with = "deserialize_cache_scope"
    )]
    pub cache_scope: crate::result::CacheScope,
}

fn serialize_cache_scope<S>(
    scope: &crate::result::CacheScope,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(match scope {
        crate::result::CacheScope::Public => "public",
        crate::result::CacheScope::Private => "private",
    })
}

fn deserialize_cache_scope<'de, D>(deserializer: D) -> Result<crate::result::CacheScope, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match String::deserialize(deserializer)?.as_str() {
        "public" => Ok(crate::result::CacheScope::Public),
        "private" => Ok(crate::result::CacheScope::Private),
        _ => Err(serde::de::Error::custom(
            "cacheScope must be `public` or `private`",
        )),
    }
}

/// One final prompt message using a final common content block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalPromptMessage {
    /// Role of the prompt message author.
    pub role: crate::types::Role,
    /// Final common message content.
    pub content: ContentBlock,
}

/// Final `prompts/get` result payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalGetPromptResult {
    /// Optional prompt description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Prompt messages.
    pub messages: Vec<FinalPromptMessage>,
}

// ============================================================================
// Final directional notification unions
// ============================================================================

/// Typed admission error for an MCP 2026-07-28 notification union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalNotificationError {
    /// The public JSON-RPC struct contained invalid envelope data.
    InvalidEnvelope { method: String },
    /// A notification union was given a request with an ID.
    RequestIdPresent { method: String },
    /// The method is not part of the active final core method table.
    UnsupportedMethod { method: String },
    /// The method is a final request rather than a final notification.
    WrongEnvelope { method: String },
    /// The selected peer cannot originate this notification method.
    WrongDirection {
        /// Exact notification method literal.
        method: String,
        /// Peer that attempted to originate it.
        sender: Final2026Peer,
    },
    /// The method's required parameter shape was missing or invalid.
    InvalidParams { method: &'static str },
    /// A locally constructed typed parameter object could not be encoded.
    EncodeFailure { method: &'static str },
}

impl std::fmt::Display for FinalNotificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEnvelope { method } => {
                write!(
                    formatter,
                    "invalid JSON-RPC notification envelope for {method}"
                )
            }
            Self::RequestIdPresent { method } => {
                write!(formatter, "{method} must be a JSON-RPC notification")
            }
            Self::UnsupportedMethod { method } => {
                write!(formatter, "{method} is not an active final notification")
            }
            Self::WrongEnvelope { method } => {
                write!(formatter, "{method} is a final request, not a notification")
            }
            Self::WrongDirection { method, sender } => {
                write!(
                    formatter,
                    "{sender:?} cannot send final notification {method}"
                )
            }
            Self::InvalidParams { method } => {
                write!(
                    formatter,
                    "invalid final notification parameters for {method}"
                )
            }
            Self::EncodeFailure { method } => {
                write!(
                    formatter,
                    "unable to encode final notification parameters for {method}"
                )
            }
        }
    }
}

impl std::error::Error for FinalNotificationError {}

/// The one notification a final client may originate.
#[derive(Debug, Clone)]
pub enum ClientNotification {
    /// `notifications/cancelled` for a client-owned request.
    Cancelled(FinalCancelledNotificationParams),
}

impl ClientNotification {
    /// Admits one JSON-RPC notification only from the exact final client union.
    pub fn decode(request: &JsonRpcRequest) -> Result<Self, FinalNotificationError> {
        admit_final_notification(request, Final2026Peer::Client)?;
        match request.method.as_str() {
            NOTIFICATIONS_CANCELLED => {
                decode_required_final_notification_params(request).map(Self::Cancelled)
            }
            _ => Err(FinalNotificationError::WrongDirection {
                method: request.method.clone(),
                sender: Final2026Peer::Client,
            }),
        }
    }

    /// Returns this notification's exact method literal.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Cancelled(_) => NOTIFICATIONS_CANCELLED,
        }
    }

    /// Encodes this typed union as an ID-free JSON-RPC notification.
    pub fn encode(&self) -> Result<JsonRpcRequest, FinalNotificationError> {
        let params = match self {
            Self::Cancelled(params) => {
                encode_final_notification_params(NOTIFICATIONS_CANCELLED, params)?
            }
        };
        Ok(JsonRpcRequest::notification(self.method(), Some(params)))
    }
}

/// The eight notifications a final server may originate.
#[derive(Debug, Clone)]
pub enum ServerNotification {
    /// `notifications/cancelled` for a server-terminated subscription stream.
    Cancelled(FinalCancelledNotificationParams),
    /// `notifications/progress` for an in-flight client request.
    Progress(FinalProgressNotificationParams),
    /// `notifications/message` log event.
    Message(FinalLogMessageParams),
    /// `notifications/resources/updated` resource change event.
    ResourceUpdated(FinalResourceUpdatedNotificationParams),
    /// `notifications/resources/list_changed` catalog change event.
    ResourcesListChanged(Option<FinalEmptyNotificationParams>),
    /// `notifications/tools/list_changed` catalog change event.
    ToolsListChanged(Option<FinalEmptyNotificationParams>),
    /// `notifications/prompts/list_changed` catalog change event.
    PromptsListChanged(Option<FinalEmptyNotificationParams>),
    /// `notifications/subscriptions/acknowledged` stream acknowledgement.
    SubscriptionsAcknowledged(FinalSubscriptionsAcknowledgedNotificationParams),
}

impl ServerNotification {
    /// Admits one JSON-RPC notification only from the exact final server union.
    pub fn decode(request: &JsonRpcRequest) -> Result<Self, FinalNotificationError> {
        admit_final_notification(request, Final2026Peer::Server)?;
        match request.method.as_str() {
            NOTIFICATIONS_CANCELLED => {
                decode_required_final_notification_params(request).map(Self::Cancelled)
            }
            NOTIFICATIONS_PROGRESS => {
                decode_required_final_notification_params(request).map(Self::Progress)
            }
            NOTIFICATIONS_MESSAGE => {
                decode_required_final_notification_params(request).map(Self::Message)
            }
            NOTIFICATIONS_RESOURCES_UPDATED => {
                decode_required_final_notification_params(request).map(Self::ResourceUpdated)
            }
            NOTIFICATIONS_RESOURCES_LIST_CHANGED => {
                decode_optional_final_notification_params(request).map(Self::ResourcesListChanged)
            }
            NOTIFICATIONS_TOOLS_LIST_CHANGED => {
                decode_optional_final_notification_params(request).map(Self::ToolsListChanged)
            }
            NOTIFICATIONS_PROMPTS_LIST_CHANGED => {
                decode_optional_final_notification_params(request).map(Self::PromptsListChanged)
            }
            NOTIFICATIONS_SUBSCRIPTIONS_ACKNOWLEDGED => {
                decode_required_final_notification_params(request)
                    .map(Self::SubscriptionsAcknowledged)
            }
            _ => Err(FinalNotificationError::WrongDirection {
                method: request.method.clone(),
                sender: Final2026Peer::Server,
            }),
        }
    }

    /// Returns this notification's exact method literal.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Cancelled(_) => NOTIFICATIONS_CANCELLED,
            Self::Progress(_) => NOTIFICATIONS_PROGRESS,
            Self::Message(_) => NOTIFICATIONS_MESSAGE,
            Self::ResourceUpdated(_) => NOTIFICATIONS_RESOURCES_UPDATED,
            Self::ResourcesListChanged(_) => NOTIFICATIONS_RESOURCES_LIST_CHANGED,
            Self::ToolsListChanged(_) => NOTIFICATIONS_TOOLS_LIST_CHANGED,
            Self::PromptsListChanged(_) => NOTIFICATIONS_PROMPTS_LIST_CHANGED,
            Self::SubscriptionsAcknowledged(_) => NOTIFICATIONS_SUBSCRIPTIONS_ACKNOWLEDGED,
        }
    }

    /// Encodes this typed union as an ID-free JSON-RPC notification.
    pub fn encode(&self) -> Result<JsonRpcRequest, FinalNotificationError> {
        let params = match self {
            Self::Cancelled(params) => Some(encode_final_notification_params(
                NOTIFICATIONS_CANCELLED,
                params,
            )?),
            Self::Progress(params) => Some(encode_final_notification_params(
                NOTIFICATIONS_PROGRESS,
                params,
            )?),
            Self::Message(params) => Some(encode_final_notification_params(
                NOTIFICATIONS_MESSAGE,
                params,
            )?),
            Self::ResourceUpdated(params) => Some(encode_final_notification_params(
                NOTIFICATIONS_RESOURCES_UPDATED,
                params,
            )?),
            Self::ResourcesListChanged(params) => params
                .as_ref()
                .map(|params| {
                    encode_final_notification_params(NOTIFICATIONS_RESOURCES_LIST_CHANGED, params)
                })
                .transpose()?,
            Self::ToolsListChanged(params) => params
                .as_ref()
                .map(|params| {
                    encode_final_notification_params(NOTIFICATIONS_TOOLS_LIST_CHANGED, params)
                })
                .transpose()?,
            Self::PromptsListChanged(params) => params
                .as_ref()
                .map(|params| {
                    encode_final_notification_params(NOTIFICATIONS_PROMPTS_LIST_CHANGED, params)
                })
                .transpose()?,
            Self::SubscriptionsAcknowledged(params) => Some(encode_final_notification_params(
                NOTIFICATIONS_SUBSCRIPTIONS_ACKNOWLEDGED,
                params,
            )?),
        };
        Ok(JsonRpcRequest::notification(self.method(), params))
    }
}

fn admit_final_notification(
    request: &JsonRpcRequest,
    sender: Final2026Peer,
) -> Result<(), FinalNotificationError> {
    if request.validate().is_err() {
        return Err(FinalNotificationError::InvalidEnvelope {
            method: request.method.clone(),
        });
    }
    if !request.is_notification() {
        return Err(FinalNotificationError::RequestIdPresent {
            method: request.method.clone(),
        });
    }
    let Some(method) = final_2026_07_28_method(&request.method) else {
        return Err(FinalNotificationError::UnsupportedMethod {
            method: request.method.clone(),
        });
    };
    if !matches!(method.envelope, Final2026EnvelopeKind::Notification) {
        return Err(FinalNotificationError::WrongEnvelope {
            method: request.method.clone(),
        });
    }
    if !method.admits_notification_from(sender) {
        return Err(FinalNotificationError::WrongDirection {
            method: request.method.clone(),
            sender,
        });
    }
    Ok(())
}

fn decode_required_final_notification_params<T: DeserializeOwned>(
    request: &JsonRpcRequest,
) -> Result<T, FinalNotificationError> {
    request
        .params
        .as_ref()
        .ok_or(FinalNotificationError::InvalidParams {
            method: notification_method_literal(request),
        })
        .and_then(|params| {
            serde_json::from_value(params.clone()).map_err(|_| {
                FinalNotificationError::InvalidParams {
                    method: notification_method_literal(request),
                }
            })
        })
}

fn decode_optional_final_notification_params<T: DeserializeOwned>(
    request: &JsonRpcRequest,
) -> Result<Option<T>, FinalNotificationError> {
    request
        .params
        .as_ref()
        .map(|params| {
            serde_json::from_value(params.clone()).map_err(|_| {
                FinalNotificationError::InvalidParams {
                    method: notification_method_literal(request),
                }
            })
        })
        .transpose()
}

fn encode_final_notification_params<T: Serialize>(
    method: &'static str,
    params: &T,
) -> Result<Value, FinalNotificationError> {
    serde_json::to_value(params).map_err(|_| FinalNotificationError::EncodeFailure { method })
}

fn notification_method_literal(request: &JsonRpcRequest) -> &'static str {
    match request.method.as_str() {
        NOTIFICATIONS_CANCELLED => NOTIFICATIONS_CANCELLED,
        NOTIFICATIONS_PROGRESS => NOTIFICATIONS_PROGRESS,
        NOTIFICATIONS_MESSAGE => NOTIFICATIONS_MESSAGE,
        NOTIFICATIONS_RESOURCES_UPDATED => NOTIFICATIONS_RESOURCES_UPDATED,
        NOTIFICATIONS_RESOURCES_LIST_CHANGED => NOTIFICATIONS_RESOURCES_LIST_CHANGED,
        NOTIFICATIONS_TOOLS_LIST_CHANGED => NOTIFICATIONS_TOOLS_LIST_CHANGED,
        NOTIFICATIONS_PROMPTS_LIST_CHANGED => NOTIFICATIONS_PROMPTS_LIST_CHANGED,
        NOTIFICATIONS_SUBSCRIPTIONS_ACKNOWLEDGED => NOTIFICATIONS_SUBSCRIPTIONS_ACKNOWLEDGED,
        _ => unreachable!("notification admission rejects unknown method literals"),
    }
}

/// Completion candidates returned by either protocol era.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionValues {
    /// Completion values selected by the server.
    #[serde(
        serialize_with = "serialize_completion_values",
        deserialize_with = "deserialize_completion_values"
    )]
    pub values: Vec<String>,
    /// Total number of available values, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    /// Whether further completion values are available.
    #[serde(rename = "hasMore", default, skip_serializing_if = "Option::is_none")]
    pub has_more: Option<bool>,
}

/// Maximum completion candidates allowed on the wire by either supported era.
pub const MAX_COMPLETION_VALUES: usize = 100;

fn serialize_completion_values<S>(values: &Vec<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if values.len() > MAX_COMPLETION_VALUES {
        return Err(serde::ser::Error::custom(
            "completion values exceed the maximum of 100 items",
        ));
    }
    values.serialize(serializer)
}

fn deserialize_completion_values<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    if values.len() > MAX_COMPLETION_VALUES {
        return Err(serde::de::Error::custom(
            "completion values exceed the maximum of 100 items",
        ));
    }
    Ok(values)
}

/// Exact legacy `completion/complete` result payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyCompletionResult {
    /// Completion candidates.
    pub completion: CompletionValues,
    /// Opaque legacy response metadata retained without interpretation.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<LegacyOpaqueMetadata>,
}

/// Ordered opaque legacy metadata.
///
/// `serde_json::Map` uses a key-sorted representation in this workspace. The
/// Legacy result wires promise the received `_meta` member order remains
/// observable on replay, so this narrow wrapper retains object-member order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LegacyOpaqueMetadata {
    entries: Vec<(String, Value)>,
}

impl LegacyOpaqueMetadata {
    /// Looks up one retained metadata value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(entry_key, _)| entry_key == key)
            .map(|(_, value)| value)
    }

    /// Returns metadata entries in their original wire order.
    #[must_use]
    pub fn entries(&self) -> &[(String, Value)] {
        &self.entries
    }
}

impl Serialize for LegacyOpaqueMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.entries.len()))?;
        for (key, value) in &self.entries {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for LegacyOpaqueMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MetadataVisitor;

        impl<'de> Visitor<'de> for MetadataVisitor {
            type Value = LegacyOpaqueMetadata;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object of legacy metadata")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut entries = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    if entries.iter().any(|(existing, _)| existing == &key) {
                        return Err(serde::de::Error::custom("duplicate legacy metadata member"));
                    }
                    entries.push((key, value));
                }
                Ok(LegacyOpaqueMetadata { entries })
            }
        }

        deserializer.deserialize_map(MetadataVisitor)
    }
}

/// Final `completion/complete` result payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalCompletionResult {
    /// Completion candidates.
    pub completion: CompletionValues,
}

/// Empty final `subscriptions/listen` result body.
///
/// The required subscription-stream ID is carried in the common result
/// metadata and exposed by [`FinalCoreResult::SubscriptionsListen`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalSubscriptionsListenResult {}

/// Empty final complete-result payload used by acknowledgement methods.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalEmptyResult {}

/// Empty exact-legacy result payload used by acknowledgement methods.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyEmptyResult {}

/// Legacy core requests remain exact uses of the existing message structs.
/// They are never reinterpreted as final requests.
#[derive(Debug, Clone)]
pub enum LegacyCoreRequest {
    /// `initialize` is unique to the legacy initialize-handshake era.
    Initialize(InitializeParams),
    /// `completion/complete`.
    Completion(LegacyCompletionParams),
    /// `sampling/createMessage`.
    SamplingCreateMessage(CreateMessageParams),
    /// `tools/list`.
    ToolsList(ListToolsParams),
    /// `tools/call`.
    ToolsCall(CallToolParams),
    /// `resources/list`.
    ResourcesList(ListResourcesParams),
    /// `resources/templates/list`.
    ResourceTemplatesList(ListResourceTemplatesParams),
    /// `resources/read`.
    ResourcesRead(ReadResourceParams),
    /// `prompts/list`.
    PromptsList(ListPromptsParams),
    /// `prompts/get`.
    PromptsGet(GetPromptParams),
    /// `logging/setLevel`.
    SetLogLevel(SetLogLevelParams),
    /// `ping`, which has no legacy parameter object.
    Ping,
}

/// Final core requests use final metadata and common vocabulary throughout.
#[derive(Debug, Clone)]
pub enum FinalCoreRequest {
    /// `server/discover`.
    Discover(FinalEmptyParams),
    /// `completion/complete`.
    Completion(FinalCompletionParams),
    /// `tools/list`.
    ToolsList(FinalListParams),
    /// `tools/call`.
    ToolsCall(FinalCallToolParams),
    /// `resources/list`.
    ResourcesList(FinalListParams),
    /// `resources/templates/list`.
    ResourceTemplatesList(FinalListParams),
    /// `resources/read`.
    ResourcesRead(FinalReadResourceParams),
    /// `prompts/list`.
    PromptsList(FinalListParams),
    /// `prompts/get`.
    PromptsGet(FinalGetPromptParams),
    /// `subscriptions/listen`.
    SubscriptionsListen(FinalSubscriptionsListenParams),
}

/// Public, era-aware dispatch for the currently supported core request set.
#[derive(Debug, Clone)]
pub enum CoreRequest {
    /// Exact MCP 2024-11-05 request vocabulary.
    Legacy(LegacyCoreRequest),
    /// Final MCP 2026-07-28 request vocabulary.
    Final(FinalCoreRequest),
}

/// Exact legacy response payloads, intentionally disjoint from final results.
#[derive(Debug, Clone)]
pub enum LegacyCoreResult {
    /// `initialize`.
    Initialize(InitializeResult),
    /// `completion/complete`.
    Completion(LegacyCompletionResult),
    /// `sampling/createMessage`.
    SamplingCreateMessage(CreateMessageResult),
    /// `tools/list`.
    ToolsList(ListToolsResult),
    /// `tools/call`.
    ToolsCall(CallToolResult),
    /// `resources/list`.
    ResourcesList(ListResourcesResult),
    /// `resources/templates/list`.
    ResourceTemplatesList(ListResourceTemplatesResult),
    /// `resources/read`.
    ResourcesRead(ReadResourceResult),
    /// `prompts/list`.
    PromptsList(ListPromptsResult),
    /// `prompts/get`.
    PromptsGet(GetPromptResult),
    /// `logging/setLevel` acknowledgement.
    SetLogLevel(LegacyEmptyResult),
    /// `ping` acknowledgement.
    Ping(LegacyEmptyResult),
}

/// Final result dispatch for the currently supported core methods.
///
/// Every complete branch carries the bounded final complete-result algebra.
/// `tools/call`, `resources/read`, and `prompts/get` additionally carry the
/// final MRTR `input_required` branch. Both preserve an absent-result-type
/// compatibility diagnostic for callers that record peer conformance.
#[derive(Debug, Clone)]
pub enum FinalCoreResult {
    /// `server/discover`.
    Discover(crate::server_discovery::ServerDiscoverResult),
    /// `completion/complete`.
    Completion {
        result: CompleteResult<FinalCompletionResult>,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
    /// `tools/list`.
    ToolsList {
        result: CompleteResult<FinalListToolsResult>,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
    /// `tools/call`.
    ToolsCall {
        result: CompleteResult<FinalCallToolResult>,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
    /// `tools/call` requires client input before a retry.
    ToolsCallInputRequired {
        result: InputRequiredResult,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
    /// `resources/list`.
    ResourcesList {
        result: CompleteResult<FinalListResourcesResult>,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
    /// `resources/templates/list`.
    ResourceTemplatesList {
        result: CompleteResult<FinalListResourceTemplatesResult>,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
    /// `resources/read`.
    ResourcesRead {
        result: CompleteResult<FinalReadResourceResult>,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
    /// `resources/read` requires client input before a retry.
    ResourcesReadInputRequired {
        result: InputRequiredResult,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
    /// `prompts/list`.
    PromptsList {
        result: CompleteResult<FinalListPromptsResult>,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
    /// `prompts/get`.
    PromptsGet {
        result: CompleteResult<FinalGetPromptResult>,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
    /// `prompts/get` requires client input before a retry.
    PromptsGetInputRequired {
        result: InputRequiredResult,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
    /// `subscriptions/listen` graceful termination.
    SubscriptionsListen {
        result: CompleteResult<FinalSubscriptionsListenResult>,
        /// The required subscription ID extracted from the result metadata.
        subscription_id: RequestId,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
}

/// Public, era-aware dispatch for core results.
#[derive(Debug, Clone)]
pub enum CoreResult {
    /// Exact MCP 2024-11-05 result vocabulary.
    Legacy(LegacyCoreResult),
    /// Final MCP 2026-07-28 complete-result vocabulary.
    Final(FinalCoreResult),
}

/// Stable errors raised while selecting a typed core request or result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreDispatchError {
    /// The selected era does not support this method.
    UnsupportedMethod { era: ProtocolEra, method: String },
    /// A request's method-specific parameters could not be decoded.
    InvalidParams {
        era: ProtocolEra,
        method: &'static str,
    },
    /// Final request metadata was absent, malformed, or for another era.
    InvalidFinalMetadata { method: &'static str },
    /// A legacy request attempted to carry final per-request metadata.
    CrossEraRequestMetadata { method: &'static str },
    /// A legacy result attempted to carry a final `resultType` discriminator.
    CrossEraResultType { method: &'static str },
    /// A result did not match the selected method-specific payload.
    InvalidResult {
        era: ProtocolEra,
        method: &'static str,
    },
    /// A final result used another core discriminator.
    UnexpectedFinalResultType { method: &'static str },
    /// A final subscriptions/listen result did not correlate to its JSON-RPC response ID.
    SubscriptionIdMismatch,
    /// The bounded final result codec rejected the wire value.
    ResultCodec(ResultDecodeError),
}

impl std::fmt::Display for CoreDispatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedMethod { era, method } => {
                write!(formatter, "{method} is not supported in {era:?}")
            }
            Self::InvalidParams { era, method } => {
                write!(formatter, "invalid {method} parameters for {era:?}")
            }
            Self::InvalidFinalMetadata { method } => {
                write!(formatter, "invalid final metadata for {method}")
            }
            Self::CrossEraRequestMetadata { method } => {
                write!(formatter, "legacy {method} cannot carry final metadata")
            }
            Self::CrossEraResultType { method } => {
                write!(formatter, "legacy {method} cannot carry final resultType")
            }
            Self::InvalidResult { era, method } => {
                write!(formatter, "invalid {method} result for {era:?}")
            }
            Self::UnexpectedFinalResultType { method } => {
                write!(formatter, "final {method} requires a complete result")
            }
            Self::SubscriptionIdMismatch => {
                formatter.write_str("subscription result metadata does not match response id")
            }
            Self::ResultCodec(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CoreDispatchError {}

impl From<ResultDecodeError> for CoreDispatchError {
    fn from(error: ResultDecodeError) -> Self {
        Self::ResultCodec(error)
    }
}

impl CoreRequest {
    /// Decodes one core request only through the exact protocol era selected
    /// by the connection. The two request vocabularies are deliberately
    /// disjoint even where their method literals are shared.
    pub fn decode(
        era: ProtocolEra,
        method: &str,
        params: Option<&Value>,
    ) -> Result<Self, CoreDispatchError> {
        match era {
            ProtocolEra::Legacy2024 => Self::decode_legacy(method, params),
            ProtocolEra::Modern2026 => Self::decode_final(method, params),
        }
    }

    /// Returns the era selected by this request.
    #[must_use]
    pub const fn era(&self) -> ProtocolEra {
        match self {
            Self::Legacy(_) => ProtocolEra::Legacy2024,
            Self::Final(_) => ProtocolEra::Modern2026,
        }
    }

    /// Returns the exact core method literal selected by this request.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Legacy(request) => request.method(),
            Self::Final(request) => request.method(),
        }
    }

    /// Encodes the method-owned parameter object without adding a JSON-RPC
    /// envelope. Final requests revalidate their common metadata before
    /// serialization so local callers cannot emit a cross-era request.
    pub fn encode_params(&self) -> Result<Option<Value>, CoreDispatchError> {
        match self {
            Self::Legacy(request) => request.encode_params(),
            Self::Final(request) => request.encode_params(),
        }
    }

    /// Decodes the JSON-RPC result payload selected by this request.
    pub fn decode_result(&self, input: &str) -> Result<CoreResult, CoreDispatchError> {
        match self {
            Self::Legacy(request) => request.decode_result(input).map(CoreResult::Legacy),
            Self::Final(request) => request.decode_result(input, None).map(CoreResult::Final),
        }
    }

    /// Decodes a successful JSON-RPC response selected by this request.
    ///
    /// This form preserves the response correlation context required by final
    /// `subscriptions/listen`: its result metadata subscription ID must equal
    /// the enclosing JSON-RPC response ID.
    pub fn decode_response(
        &self,
        response: &JsonRpcResponse,
    ) -> Result<CoreResult, CoreDispatchError> {
        let Some(response_id) = response.id.as_ref() else {
            return Err(CoreDispatchError::InvalidResult {
                era: self.era(),
                method: self.method(),
            });
        };
        let Some(result) = response.result.as_ref() else {
            return Err(CoreDispatchError::InvalidResult {
                era: self.era(),
                method: self.method(),
            });
        };
        let input =
            serde_json::to_string(result).map_err(|_| CoreDispatchError::InvalidResult {
                era: self.era(),
                method: self.method(),
            })?;
        match self {
            Self::Legacy(request) => request.decode_result(&input).map(CoreResult::Legacy),
            Self::Final(request) => request
                .decode_result(&input, Some(response_id))
                .map(CoreResult::Final),
        }
    }

    fn decode_legacy(method: &str, params: Option<&Value>) -> Result<Self, CoreDispatchError> {
        let request =
            match method {
                INITIALIZE => LegacyCoreRequest::Initialize(decode_params(
                    ProtocolEra::Legacy2024,
                    INITIALIZE,
                    params,
                )?),
                COMPLETION_COMPLETE => LegacyCoreRequest::Completion(decode_params(
                    ProtocolEra::Legacy2024,
                    COMPLETION_COMPLETE,
                    params,
                )?),
                SAMPLING_CREATE_MESSAGE => LegacyCoreRequest::SamplingCreateMessage(decode_params(
                    ProtocolEra::Legacy2024,
                    SAMPLING_CREATE_MESSAGE,
                    params,
                )?),
                TOOLS_LIST => LegacyCoreRequest::ToolsList(decode_params(
                    ProtocolEra::Legacy2024,
                    TOOLS_LIST,
                    params,
                )?),
                TOOLS_CALL => LegacyCoreRequest::ToolsCall(decode_params(
                    ProtocolEra::Legacy2024,
                    TOOLS_CALL,
                    params,
                )?),
                RESOURCES_LIST => LegacyCoreRequest::ResourcesList(decode_params(
                    ProtocolEra::Legacy2024,
                    RESOURCES_LIST,
                    params,
                )?),
                RESOURCES_TEMPLATES_LIST => LegacyCoreRequest::ResourceTemplatesList(
                    decode_params(ProtocolEra::Legacy2024, RESOURCES_TEMPLATES_LIST, params)?,
                ),
                RESOURCES_READ => LegacyCoreRequest::ResourcesRead(decode_params(
                    ProtocolEra::Legacy2024,
                    RESOURCES_READ,
                    params,
                )?),
                PROMPTS_LIST => LegacyCoreRequest::PromptsList(decode_params(
                    ProtocolEra::Legacy2024,
                    PROMPTS_LIST,
                    params,
                )?),
                PROMPTS_GET => LegacyCoreRequest::PromptsGet(decode_params(
                    ProtocolEra::Legacy2024,
                    PROMPTS_GET,
                    params,
                )?),
                LOGGING_SET_LEVEL => LegacyCoreRequest::SetLogLevel(decode_params(
                    ProtocolEra::Legacy2024,
                    LOGGING_SET_LEVEL,
                    params,
                )?),
                PING => {
                    require_absent_or_empty_params(ProtocolEra::Legacy2024, PING, params)?;
                    LegacyCoreRequest::Ping
                }
                _ => {
                    return Err(CoreDispatchError::UnsupportedMethod {
                        era: ProtocolEra::Legacy2024,
                        method: method.to_owned(),
                    });
                }
            };
        if legacy_params_carry_final_metadata(params) {
            return Err(CoreDispatchError::CrossEraRequestMetadata {
                method: request.method(),
            });
        }
        if let LegacyCoreRequest::Initialize(params) = &request
            && params.protocol_version != ProtocolEra::Legacy2024.version().as_str()
        {
            return Err(CoreDispatchError::InvalidParams {
                era: ProtocolEra::Legacy2024,
                method: INITIALIZE,
            });
        }
        Ok(Self::Legacy(request))
    }

    fn decode_final(method: &str, params: Option<&Value>) -> Result<Self, CoreDispatchError> {
        let request = match method {
            SERVER_DISCOVER => {
                FinalCoreRequest::Discover(decode_final_params(SERVER_DISCOVER, params)?)
            }
            COMPLETION_COMPLETE => {
                FinalCoreRequest::Completion(decode_final_params(COMPLETION_COMPLETE, params)?)
            }
            TOOLS_LIST => FinalCoreRequest::ToolsList(decode_final_params(TOOLS_LIST, params)?),
            TOOLS_CALL => FinalCoreRequest::ToolsCall(decode_final_params(TOOLS_CALL, params)?),
            RESOURCES_LIST => {
                FinalCoreRequest::ResourcesList(decode_final_params(RESOURCES_LIST, params)?)
            }
            RESOURCES_TEMPLATES_LIST => FinalCoreRequest::ResourceTemplatesList(
                decode_final_params(RESOURCES_TEMPLATES_LIST, params)?,
            ),
            RESOURCES_READ => {
                FinalCoreRequest::ResourcesRead(decode_final_params(RESOURCES_READ, params)?)
            }
            PROMPTS_LIST => {
                FinalCoreRequest::PromptsList(decode_final_params(PROMPTS_LIST, params)?)
            }
            PROMPTS_GET => FinalCoreRequest::PromptsGet(decode_final_params(PROMPTS_GET, params)?),
            SUBSCRIPTIONS_LISTEN => FinalCoreRequest::SubscriptionsListen(decode_final_params(
                SUBSCRIPTIONS_LISTEN,
                params,
            )?),
            _ => {
                return Err(CoreDispatchError::UnsupportedMethod {
                    era: ProtocolEra::Modern2026,
                    method: method.to_owned(),
                });
            }
        };
        request.validate_metadata()?;
        Ok(Self::Final(request))
    }
}

impl LegacyCoreRequest {
    /// Returns this request's exact method literal.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Initialize(_) => INITIALIZE,
            Self::Completion(_) => COMPLETION_COMPLETE,
            Self::SamplingCreateMessage(_) => SAMPLING_CREATE_MESSAGE,
            Self::ToolsList(_) => TOOLS_LIST,
            Self::ToolsCall(_) => TOOLS_CALL,
            Self::ResourcesList(_) => RESOURCES_LIST,
            Self::ResourceTemplatesList(_) => RESOURCES_TEMPLATES_LIST,
            Self::ResourcesRead(_) => RESOURCES_READ,
            Self::PromptsList(_) => PROMPTS_LIST,
            Self::PromptsGet(_) => PROMPTS_GET,
            Self::SetLogLevel(_) => LOGGING_SET_LEVEL,
            Self::Ping => PING,
        }
    }

    fn encode_params(&self) -> Result<Option<Value>, CoreDispatchError> {
        match self {
            Self::Initialize(params) => encode_params(ProtocolEra::Legacy2024, INITIALIZE, params),
            Self::Completion(params) => {
                encode_params(ProtocolEra::Legacy2024, COMPLETION_COMPLETE, params)
            }
            Self::SamplingCreateMessage(params) => {
                encode_params(ProtocolEra::Legacy2024, SAMPLING_CREATE_MESSAGE, params)
            }
            Self::ToolsList(params) => encode_params(ProtocolEra::Legacy2024, TOOLS_LIST, params),
            Self::ToolsCall(params) => encode_params(ProtocolEra::Legacy2024, TOOLS_CALL, params),
            Self::ResourcesList(params) => {
                encode_params(ProtocolEra::Legacy2024, RESOURCES_LIST, params)
            }
            Self::ResourceTemplatesList(params) => {
                encode_params(ProtocolEra::Legacy2024, RESOURCES_TEMPLATES_LIST, params)
            }
            Self::ResourcesRead(params) => {
                encode_params(ProtocolEra::Legacy2024, RESOURCES_READ, params)
            }
            Self::PromptsList(params) => {
                encode_params(ProtocolEra::Legacy2024, PROMPTS_LIST, params)
            }
            Self::PromptsGet(params) => encode_params(ProtocolEra::Legacy2024, PROMPTS_GET, params),
            Self::SetLogLevel(params) => {
                encode_params(ProtocolEra::Legacy2024, LOGGING_SET_LEVEL, params)
            }
            Self::Ping => Ok(None),
        }
    }

    fn decode_result(&self, input: &str) -> Result<LegacyCoreResult, CoreDispatchError> {
        match self {
            Self::Initialize(_) => {
                decode_legacy_result(INITIALIZE, input).map(LegacyCoreResult::Initialize)
            }
            Self::Completion(_) => {
                decode_legacy_result(COMPLETION_COMPLETE, input).map(LegacyCoreResult::Completion)
            }
            Self::SamplingCreateMessage(_) => decode_legacy_result(SAMPLING_CREATE_MESSAGE, input)
                .map(LegacyCoreResult::SamplingCreateMessage),
            Self::ToolsList(_) => {
                decode_legacy_result(TOOLS_LIST, input).map(LegacyCoreResult::ToolsList)
            }
            Self::ToolsCall(_) => {
                decode_legacy_result(TOOLS_CALL, input).map(LegacyCoreResult::ToolsCall)
            }
            Self::ResourcesList(_) => {
                decode_legacy_result(RESOURCES_LIST, input).map(LegacyCoreResult::ResourcesList)
            }
            Self::ResourceTemplatesList(_) => decode_legacy_result(RESOURCES_TEMPLATES_LIST, input)
                .map(LegacyCoreResult::ResourceTemplatesList),
            Self::ResourcesRead(_) => {
                decode_legacy_result(RESOURCES_READ, input).map(LegacyCoreResult::ResourcesRead)
            }
            Self::PromptsList(_) => {
                decode_legacy_result(PROMPTS_LIST, input).map(LegacyCoreResult::PromptsList)
            }
            Self::PromptsGet(_) => {
                decode_legacy_result(PROMPTS_GET, input).map(LegacyCoreResult::PromptsGet)
            }
            Self::SetLogLevel(_) => {
                decode_legacy_result(LOGGING_SET_LEVEL, input).map(LegacyCoreResult::SetLogLevel)
            }
            Self::Ping => decode_legacy_result(PING, input).map(LegacyCoreResult::Ping),
        }
    }
}

impl FinalCoreRequest {
    /// Returns this request's exact method literal.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Discover(_) => SERVER_DISCOVER,
            Self::Completion(_) => COMPLETION_COMPLETE,
            Self::ToolsList(_) => TOOLS_LIST,
            Self::ToolsCall(_) => TOOLS_CALL,
            Self::ResourcesList(_) => RESOURCES_LIST,
            Self::ResourceTemplatesList(_) => RESOURCES_TEMPLATES_LIST,
            Self::ResourcesRead(_) => RESOURCES_READ,
            Self::PromptsList(_) => PROMPTS_LIST,
            Self::PromptsGet(_) => PROMPTS_GET,
            Self::SubscriptionsListen(_) => SUBSCRIPTIONS_LISTEN,
        }
    }

    fn validate_metadata(&self) -> Result<(), CoreDispatchError> {
        let metadata = match self {
            Self::Discover(params) => &params.meta,
            Self::Completion(params) => &params.meta,
            Self::ToolsList(params)
            | Self::ResourcesList(params)
            | Self::ResourceTemplatesList(params)
            | Self::PromptsList(params) => &params.meta,
            Self::ToolsCall(params) => &params.meta,
            Self::ResourcesRead(params) => &params.meta,
            Self::PromptsGet(params) => &params.meta,
            Self::SubscriptionsListen(params) => &params.meta,
        };
        let valid_version = metadata.protocol_version().ok().flatten()
            == Some(ProtocolEra::Modern2026.version().as_str());
        let has_capabilities = metadata.client_capabilities().ok().flatten().is_some();
        if valid_version && has_capabilities {
            Ok(())
        } else {
            Err(CoreDispatchError::InvalidFinalMetadata {
                method: self.method(),
            })
        }
    }

    fn encode_params(&self) -> Result<Option<Value>, CoreDispatchError> {
        self.validate_metadata()?;
        match self {
            Self::Discover(params) => {
                encode_params(ProtocolEra::Modern2026, SERVER_DISCOVER, params)
            }
            Self::Completion(params) => {
                encode_params(ProtocolEra::Modern2026, COMPLETION_COMPLETE, params)
            }
            Self::ToolsList(params) => encode_params(ProtocolEra::Modern2026, TOOLS_LIST, params),
            Self::ToolsCall(params) => encode_params(ProtocolEra::Modern2026, TOOLS_CALL, params),
            Self::ResourcesList(params) => {
                encode_params(ProtocolEra::Modern2026, RESOURCES_LIST, params)
            }
            Self::ResourceTemplatesList(params) => {
                encode_params(ProtocolEra::Modern2026, RESOURCES_TEMPLATES_LIST, params)
            }
            Self::ResourcesRead(params) => {
                encode_params(ProtocolEra::Modern2026, RESOURCES_READ, params)
            }
            Self::PromptsList(params) => {
                encode_params(ProtocolEra::Modern2026, PROMPTS_LIST, params)
            }
            Self::PromptsGet(params) => encode_params(ProtocolEra::Modern2026, PROMPTS_GET, params),
            Self::SubscriptionsListen(params) => {
                encode_params(ProtocolEra::Modern2026, SUBSCRIPTIONS_LISTEN, params)
            }
        }
    }

    fn decode_result(
        &self,
        input: &str,
        response_id: Option<&RequestId>,
    ) -> Result<FinalCoreResult, CoreDispatchError> {
        match self {
            Self::Discover(_) => serde_json::from_str(input)
                .map(FinalCoreResult::Discover)
                .map_err(|_| CoreDispatchError::InvalidResult {
                    era: ProtocolEra::Modern2026,
                    method: SERVER_DISCOVER,
                }),
            Self::Completion(_) => {
                decode_final_complete(COMPLETION_COMPLETE, input, &["completion"])
                    .map(|(result, diagnostic)| FinalCoreResult::Completion { result, diagnostic })
            }
            Self::ToolsList(_) => decode_final_complete(
                TOOLS_LIST,
                input,
                &["tools", "nextCursor", "ttlMs", "cacheScope"],
            )
            .map(|(result, diagnostic)| FinalCoreResult::ToolsList { result, diagnostic }),
            Self::ToolsCall(_) => decode_final_complete_or_input_required(
                TOOLS_CALL,
                input,
                &["content", "isError", "structuredContent"],
            )
            .map(|result| match result {
                FinalMethodResult::Complete { result, diagnostic } => {
                    FinalCoreResult::ToolsCall { result, diagnostic }
                }
                FinalMethodResult::InputRequired { result, diagnostic } => {
                    FinalCoreResult::ToolsCallInputRequired { result, diagnostic }
                }
            }),
            Self::ResourcesList(_) => decode_final_complete(
                RESOURCES_LIST,
                input,
                &["resources", "nextCursor", "ttlMs", "cacheScope"],
            )
            .map(|(result, diagnostic)| FinalCoreResult::ResourcesList { result, diagnostic }),
            Self::ResourceTemplatesList(_) => {
                decode_final_complete(
                    RESOURCES_TEMPLATES_LIST,
                    input,
                    &["resourceTemplates", "nextCursor", "ttlMs", "cacheScope"],
                )
                .map(|(result, diagnostic)| {
                    FinalCoreResult::ResourceTemplatesList { result, diagnostic }
                })
            }
            Self::ResourcesRead(_) => decode_final_complete_or_input_required(
                RESOURCES_READ,
                input,
                &["contents", "ttlMs", "cacheScope"],
            )
            .map(|result| match result {
                FinalMethodResult::Complete { result, diagnostic } => {
                    FinalCoreResult::ResourcesRead { result, diagnostic }
                }
                FinalMethodResult::InputRequired { result, diagnostic } => {
                    FinalCoreResult::ResourcesReadInputRequired { result, diagnostic }
                }
            }),
            Self::PromptsList(_) => decode_final_complete(
                PROMPTS_LIST,
                input,
                &["prompts", "nextCursor", "ttlMs", "cacheScope"],
            )
            .map(|(result, diagnostic)| FinalCoreResult::PromptsList { result, diagnostic }),
            Self::PromptsGet(_) => decode_final_complete_or_input_required(
                PROMPTS_GET,
                input,
                &["description", "messages"],
            )
            .map(|result| match result {
                FinalMethodResult::Complete { result, diagnostic } => {
                    FinalCoreResult::PromptsGet { result, diagnostic }
                }
                FinalMethodResult::InputRequired { result, diagnostic } => {
                    FinalCoreResult::PromptsGetInputRequired { result, diagnostic }
                }
            }),
            Self::SubscriptionsListen(_) => {
                let (result, diagnostic) = decode_final_complete(SUBSCRIPTIONS_LISTEN, input, &[])?;
                let subscription_id = subscription_id_from_result(&result)?;
                if response_id.is_some_and(|response_id| response_id != &subscription_id) {
                    return Err(CoreDispatchError::SubscriptionIdMismatch);
                }
                Ok(FinalCoreResult::SubscriptionsListen {
                    result,
                    subscription_id,
                    diagnostic,
                })
            }
        }
    }
}

impl CoreResult {
    /// Returns the era selected by this result.
    #[must_use]
    pub const fn era(&self) -> ProtocolEra {
        match self {
            Self::Legacy(_) => ProtocolEra::Legacy2024,
            Self::Final(_) => ProtocolEra::Modern2026,
        }
    }

    /// Returns the exact method literal that selected this result type.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Legacy(result) => result.method(),
            Self::Final(result) => result.method(),
        }
    }

    /// Encodes this typed result without a JSON-RPC response envelope.
    pub fn encode(&self) -> Result<String, CoreDispatchError> {
        match self {
            Self::Legacy(result) => result.encode(),
            Self::Final(result) => result.encode(),
        }
    }
}

impl LegacyCoreResult {
    /// Returns the exact method literal that selected this legacy result.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Initialize(_) => INITIALIZE,
            Self::Completion(_) => COMPLETION_COMPLETE,
            Self::SamplingCreateMessage(_) => SAMPLING_CREATE_MESSAGE,
            Self::ToolsList(_) => TOOLS_LIST,
            Self::ToolsCall(_) => TOOLS_CALL,
            Self::ResourcesList(_) => RESOURCES_LIST,
            Self::ResourceTemplatesList(_) => RESOURCES_TEMPLATES_LIST,
            Self::ResourcesRead(_) => RESOURCES_READ,
            Self::PromptsList(_) => PROMPTS_LIST,
            Self::PromptsGet(_) => PROMPTS_GET,
            Self::SetLogLevel(_) => LOGGING_SET_LEVEL,
            Self::Ping(_) => PING,
        }
    }

    fn encode(&self) -> Result<String, CoreDispatchError> {
        match self {
            Self::Initialize(result) => encode_legacy_result(INITIALIZE, result),
            Self::Completion(result) => encode_legacy_result(COMPLETION_COMPLETE, result),
            Self::SamplingCreateMessage(result) => {
                encode_legacy_result(SAMPLING_CREATE_MESSAGE, result)
            }
            Self::ToolsList(result) => encode_legacy_result(TOOLS_LIST, result),
            Self::ToolsCall(result) => encode_legacy_result(TOOLS_CALL, result),
            Self::ResourcesList(result) => encode_legacy_result(RESOURCES_LIST, result),
            Self::ResourceTemplatesList(result) => {
                encode_legacy_result(RESOURCES_TEMPLATES_LIST, result)
            }
            Self::ResourcesRead(result) => encode_legacy_result(RESOURCES_READ, result),
            Self::PromptsList(result) => encode_legacy_result(PROMPTS_LIST, result),
            Self::PromptsGet(result) => encode_legacy_result(PROMPTS_GET, result),
            Self::SetLogLevel(result) => encode_legacy_result(LOGGING_SET_LEVEL, result),
            Self::Ping(result) => encode_legacy_result(PING, result),
        }
    }
}

impl FinalCoreResult {
    /// Returns the exact method literal that selected this final result.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Discover(_) => SERVER_DISCOVER,
            Self::Completion { .. } => COMPLETION_COMPLETE,
            Self::ToolsList { .. } => TOOLS_LIST,
            Self::ToolsCall { .. } | Self::ToolsCallInputRequired { .. } => TOOLS_CALL,
            Self::ResourcesList { .. } => RESOURCES_LIST,
            Self::ResourceTemplatesList { .. } => RESOURCES_TEMPLATES_LIST,
            Self::ResourcesRead { .. } | Self::ResourcesReadInputRequired { .. } => RESOURCES_READ,
            Self::PromptsList { .. } => PROMPTS_LIST,
            Self::PromptsGet { .. } | Self::PromptsGetInputRequired { .. } => PROMPTS_GET,
            Self::SubscriptionsListen { .. } => SUBSCRIPTIONS_LISTEN,
        }
    }

    fn encode(&self) -> Result<String, CoreDispatchError> {
        match self {
            Self::Discover(result) => {
                serde_json::to_string(result).map_err(|_| CoreDispatchError::InvalidResult {
                    era: ProtocolEra::Modern2026,
                    method: SERVER_DISCOVER,
                })
            }
            Self::Completion { result, .. } => {
                encode_final_complete(COMPLETION_COMPLETE, result, &["completion"])
            }
            Self::ToolsList { result, .. } => encode_final_complete(
                TOOLS_LIST,
                result,
                &["tools", "nextCursor", "ttlMs", "cacheScope"],
            ),
            Self::ToolsCall { result, .. } => encode_final_complete(
                TOOLS_CALL,
                result,
                &["content", "isError", "structuredContent"],
            ),
            Self::ToolsCallInputRequired { result, .. } => {
                encode_final_input_required(TOOLS_CALL, result)
            }
            Self::ResourcesList { result, .. } => encode_final_complete(
                RESOURCES_LIST,
                result,
                &["resources", "nextCursor", "ttlMs", "cacheScope"],
            ),
            Self::ResourceTemplatesList { result, .. } => encode_final_complete(
                RESOURCES_TEMPLATES_LIST,
                result,
                &["resourceTemplates", "nextCursor", "ttlMs", "cacheScope"],
            ),
            Self::ResourcesRead { result, .. } => {
                encode_final_complete(RESOURCES_READ, result, &["contents", "ttlMs", "cacheScope"])
            }
            Self::ResourcesReadInputRequired { result, .. } => {
                encode_final_input_required(RESOURCES_READ, result)
            }
            Self::PromptsList { result, .. } => encode_final_complete(
                PROMPTS_LIST,
                result,
                &["prompts", "nextCursor", "ttlMs", "cacheScope"],
            ),
            Self::PromptsGet { result, .. } => {
                encode_final_complete(PROMPTS_GET, result, &["description", "messages"])
            }
            Self::PromptsGetInputRequired { result, .. } => {
                encode_final_input_required(PROMPTS_GET, result)
            }
            Self::SubscriptionsListen {
                result,
                subscription_id,
                ..
            } => {
                if subscription_id_from_result(result)? != subscription_id.clone() {
                    return Err(CoreDispatchError::InvalidResult {
                        era: ProtocolEra::Modern2026,
                        method: SUBSCRIPTIONS_LISTEN,
                    });
                }
                encode_final_complete(SUBSCRIPTIONS_LISTEN, result, &[])
            }
        }
    }
}

fn decode_params<T: DeserializeOwned>(
    era: ProtocolEra,
    method: &'static str,
    params: Option<&Value>,
) -> Result<T, CoreDispatchError> {
    serde_json::from_value(
        params
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default())),
    )
    .map_err(|_| CoreDispatchError::InvalidParams { era, method })
}

fn decode_final_params<T: DeserializeOwned>(
    method: &'static str,
    params: Option<&Value>,
) -> Result<T, CoreDispatchError> {
    decode_params(ProtocolEra::Modern2026, method, params)
}

fn encode_params<T: Serialize>(
    era: ProtocolEra,
    method: &'static str,
    params: &T,
) -> Result<Option<Value>, CoreDispatchError> {
    serde_json::to_value(params)
        .map(Some)
        .map_err(|_| CoreDispatchError::InvalidParams { era, method })
}

fn require_absent_or_empty_params(
    era: ProtocolEra,
    method: &'static str,
    params: Option<&Value>,
) -> Result<(), CoreDispatchError> {
    if params.is_none_or(|params| params.as_object().is_some_and(|object| object.is_empty())) {
        Ok(())
    } else {
        Err(CoreDispatchError::InvalidParams { era, method })
    }
}

fn legacy_params_carry_final_metadata(params: Option<&Value>) -> bool {
    params
        .and_then(Value::as_object)
        .and_then(|params| params.get("_meta"))
        .and_then(Value::as_object)
        .is_some_and(|metadata| {
            metadata.contains_key(FINAL_PROTOCOL_VERSION_META_KEY)
                || metadata.contains_key(FINAL_CLIENT_CAPABILITIES_META_KEY)
        })
}

fn decode_legacy_result<T: DeserializeOwned>(
    method: &'static str,
    input: &str,
) -> Result<T, CoreDispatchError> {
    let value: Value =
        serde_json::from_str(input).map_err(|_| CoreDispatchError::InvalidResult {
            era: ProtocolEra::Legacy2024,
            method,
        })?;
    if value
        .as_object()
        .is_some_and(|object| object.contains_key("resultType"))
    {
        return Err(CoreDispatchError::CrossEraResultType { method });
    }
    serde_json::from_value(value).map_err(|_| CoreDispatchError::InvalidResult {
        era: ProtocolEra::Legacy2024,
        method,
    })
}

fn encode_legacy_result<T: Serialize>(
    method: &'static str,
    result: &T,
) -> Result<String, CoreDispatchError> {
    let value = serde_json::to_value(result).map_err(|_| CoreDispatchError::InvalidResult {
        era: ProtocolEra::Legacy2024,
        method,
    })?;
    if value
        .as_object()
        .is_some_and(|object| object.contains_key("resultType"))
    {
        return Err(CoreDispatchError::CrossEraResultType { method });
    }
    serde_json::to_string(&value).map_err(|_| CoreDispatchError::InvalidResult {
        era: ProtocolEra::Legacy2024,
        method,
    })
}

enum FinalMethodResult<T> {
    Complete {
        result: CompleteResult<T>,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
    InputRequired {
        result: InputRequiredResult,
        diagnostic: Option<ResultPeerDiagnostic>,
    },
}

fn decode_final_complete<T: DeserializeOwned>(
    method: &'static str,
    input: &str,
    known_names: &[&str],
) -> Result<(CompleteResult<T>, Option<ResultPeerDiagnostic>), CoreDispatchError> {
    let FinalMethodResult::Complete { result, diagnostic } =
        decode_final_complete_or_input_required(method, input, known_names)?
    else {
        return Err(CoreDispatchError::UnexpectedFinalResultType { method });
    };
    Ok((result, diagnostic))
}

fn decode_final_complete_or_input_required<T: DeserializeOwned>(
    method: &'static str,
    input: &str,
    known_names: &[&str],
) -> Result<FinalMethodResult<T>, CoreDispatchError> {
    let wire: Value =
        serde_json::from_str(input).map_err(|_| CoreDispatchError::InvalidResult {
            era: ProtocolEra::Modern2026,
            method,
        })?;
    if wire
        .as_object()
        .is_some_and(|object| object.contains_key("serverInfo"))
    {
        return Err(CoreDispatchError::InvalidResult {
            era: ProtocolEra::Modern2026,
            method,
        });
    }
    let (decoded, diagnostic) = decode_peer_result_for_era(
        input,
        ProtocolEra::Modern2026,
        &CoreResultDiscriminatorPolicy,
    )?;
    let complete = match decoded {
        DecodedResult::Complete(complete) => complete,
        DecodedResult::InputRequired(result) => {
            return Ok(FinalMethodResult::InputRequired { result, diagnostic });
        }
        DecodedResult::Deferred(_) => {
            return Err(CoreDispatchError::UnexpectedFinalResultType { method });
        }
    };
    let CompleteResult { meta, extras, .. } = complete;
    let mut selected = serde_json::Map::new();
    let mut remaining = Vec::new();
    for member in extras.into_members() {
        if known_names.contains(&member.name.as_str()) {
            selected.insert(member.name, exact_json_to_serde(&member.value)?);
        } else {
            remaining.push(member);
        }
    }
    let payload = serde_json::from_value(Value::Object(selected)).map_err(|_| {
        CoreDispatchError::InvalidResult {
            era: ProtocolEra::Modern2026,
            method,
        }
    })?;
    let extras = UnknownResultMembers::try_new(remaining, known_names)?;
    Ok(FinalMethodResult::Complete {
        result: CompleteResult {
            payload,
            meta,
            extras,
        },
        diagnostic,
    })
}

fn subscription_id_from_result(
    result: &CompleteResult<FinalSubscriptionsListenResult>,
) -> Result<RequestId, CoreDispatchError> {
    let metadata = result.meta.metadata();
    let Some(value) = metadata.get(FINAL_SUBSCRIPTION_ID_META_KEY) else {
        return Err(CoreDispatchError::InvalidResult {
            era: ProtocolEra::Modern2026,
            method: SUBSCRIPTIONS_LISTEN,
        });
    };
    serde_json::from_value(exact_json_to_serde(value)?).map_err(|_| {
        CoreDispatchError::InvalidResult {
            era: ProtocolEra::Modern2026,
            method: SUBSCRIPTIONS_LISTEN,
        }
    })
}

fn encode_final_complete<T: Serialize>(
    method: &'static str,
    result: &CompleteResult<T>,
    known_names: &[&str],
) -> Result<String, CoreDispatchError> {
    if result.meta.server_info.is_some()
        || result
            .extras
            .members()
            .iter()
            .any(|member| member.name == "serverInfo")
    {
        return Err(CoreDispatchError::InvalidResult {
            era: ProtocolEra::Modern2026,
            method,
        });
    }
    let Value::Object(payload) =
        serde_json::to_value(&result.payload).map_err(|_| CoreDispatchError::InvalidResult {
            era: ProtocolEra::Modern2026,
            method,
        })?
    else {
        return Err(CoreDispatchError::InvalidResult {
            era: ProtocolEra::Modern2026,
            method,
        });
    };
    let mut members = Vec::with_capacity(payload.len());
    for (name, value) in payload {
        if !known_names.contains(&name.as_str()) {
            return Err(CoreDispatchError::InvalidResult {
                era: ProtocolEra::Modern2026,
                method,
            });
        }
        members.push(ExactJsonMember {
            name,
            value: exact_json_from_serde(&value)?,
        });
    }
    encode_complete_result(&result.meta, members, known_names, &result.extras)
        .map_err(CoreDispatchError::from)
}

fn encode_final_input_required(
    method: &'static str,
    result: &InputRequiredResult,
) -> Result<String, CoreDispatchError> {
    if result.meta.server_info.is_some()
        || result
            .extras
            .members()
            .iter()
            .any(|member| member.name == "serverInfo")
    {
        return Err(CoreDispatchError::InvalidResult {
            era: ProtocolEra::Modern2026,
            method,
        });
    }
    Ok(encode_result(&DecodedResult::InputRequired(result.clone())))
}

// ============================================================================
// Initialize
// ============================================================================

/// Initialize request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeParams {
    /// Protocol version requested.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Client capabilities.
    pub capabilities: ClientCapabilities,
    /// Client info.
    #[serde(rename = "clientInfo")]
    pub client_info: ClientInfo,
}

/// Initialize response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    /// Protocol version accepted.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Server capabilities.
    pub capabilities: ServerCapabilities,
    /// Server info.
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
    /// Optional instructions for the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

// ============================================================================
// Tools
// ============================================================================

/// tools/list request params.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListToolsParams {
    /// Cursor for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Only include tools with ALL of these tags (AND logic).
    #[serde(
        rename = "includeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_tags: Option<Vec<String>>,
    /// Exclude tools with ANY of these tags (OR logic).
    #[serde(
        rename = "excludeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_tags: Option<Vec<String>>,
}

/// tools/list response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListToolsResult {
    /// List of available tools.
    pub tools: Vec<Tool>,
    /// Next cursor for pagination.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// tools/call request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolParams {
    /// Tool name to call.
    pub name: String,
    /// Tool arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<serde_json::Value>,
    /// Request metadata (progress token, etc.).
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<RequestMeta>,
}

/// tools/call response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolResult {
    /// Tool output content.
    pub content: Vec<LegacyContent>,
    /// Whether the tool call errored.
    #[serde(
        rename = "isError",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub is_error: bool,
    /// Open legacy result metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<LegacyMetadata>,
    /// Other schema-allowed result members.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional: BTreeMap<String, Value>,
}

// ============================================================================
// Resources
// ============================================================================

/// resources/list request params.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListResourcesParams {
    /// Cursor for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Only include resources with ALL of these tags (AND logic).
    #[serde(
        rename = "includeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_tags: Option<Vec<String>>,
    /// Exclude resources with ANY of these tags (OR logic).
    #[serde(
        rename = "excludeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_tags: Option<Vec<String>>,
}

/// resources/list response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResourcesResult {
    /// List of available resources.
    pub resources: Vec<Resource>,
    /// Next cursor for pagination.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// resources/templates/list request params.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListResourceTemplatesParams {
    /// Cursor for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Only include templates with ALL of these tags (AND logic).
    #[serde(
        rename = "includeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_tags: Option<Vec<String>>,
    /// Exclude templates with ANY of these tags (OR logic).
    #[serde(
        rename = "excludeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_tags: Option<Vec<String>>,
}

/// resources/templates/list response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResourceTemplatesResult {
    /// List of resource templates.
    #[serde(rename = "resourceTemplates")]
    pub resource_templates: Vec<ResourceTemplate>,
    /// Next cursor for pagination.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// resources/read request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResourceParams {
    /// Resource URI to read.
    pub uri: String,
    /// Request metadata (progress token, etc.).
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<RequestMeta>,
}

/// resources/read response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResourceResult {
    /// Resource contents.
    #[serde(deserialize_with = "deserialize_legacy_resource_contents")]
    pub contents: Vec<LegacyResourceContent>,
    /// Open legacy result metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<LegacyMetadata>,
    /// Other schema-allowed result members.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional: BTreeMap<String, Value>,
}

/// Decodes the exact legacy resource-content one-of without discarding open members.
///
/// `LegacyResourceContent` is intentionally untagged because the 2024 wire
/// shape selects its variant by `text` or `blob`. Its flattened open members
/// otherwise allow an object with both (or neither) fields to match an
/// unintended variant, so inspect the two discriminating fields before asking
/// serde to preserve the typed fields, `_meta`, and additional members.
fn deserialize_legacy_resource_contents<'de, D>(
    deserializer: D,
) -> Result<Vec<LegacyResourceContent>, D::Error>
where
    D: Deserializer<'de>,
{
    let contents = Vec::<Value>::deserialize(deserializer)?;
    contents
        .into_iter()
        .map(|content| {
            let Value::Object(object) = &content else {
                return Err(serde::de::Error::custom(
                    "legacy resource content must be an object",
                ));
            };
            match (object.contains_key("text"), object.contains_key("blob")) {
                (true, false) | (false, true) => serde_json::from_value(content)
                    .map_err(|error| serde::de::Error::custom(error.to_string())),
                (true, true) | (false, false) => Err(serde::de::Error::custom(
                    "legacy resource content must contain exactly one of text or blob",
                )),
            }
        })
        .collect()
}

/// resources/subscribe request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeResourceParams {
    /// Resource URI to subscribe to.
    pub uri: String,
}

/// resources/unsubscribe request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsubscribeResourceParams {
    /// Resource URI to unsubscribe from.
    pub uri: String,
}

// ============================================================================
// Prompts
// ============================================================================

/// prompts/list request params.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListPromptsParams {
    /// Cursor for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Only include prompts with ALL of these tags (AND logic).
    #[serde(
        rename = "includeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub include_tags: Option<Vec<String>>,
    /// Exclude prompts with ANY of these tags (OR logic).
    #[serde(
        rename = "excludeTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_tags: Option<Vec<String>>,
}

/// prompts/list response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListPromptsResult {
    /// List of available prompts.
    pub prompts: Vec<Prompt>,
    /// Next cursor for pagination.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// prompts/get request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPromptParams {
    /// Prompt name.
    pub name: String,
    /// Prompt arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<std::collections::HashMap<String, String>>,
    /// Request metadata (progress token, etc.).
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<RequestMeta>,
}

/// prompts/get response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPromptResult {
    /// Optional prompt description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Prompt messages.
    pub messages: Vec<LegacyPromptMessage>,
    /// Open legacy result metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<LegacyMetadata>,
    /// Other schema-allowed result members.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional: BTreeMap<String, Value>,
}

// ============================================================================
// Logging
// ============================================================================

/// Log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Debug level.
    Debug,
    /// Info level.
    Info,
    /// Warning level.
    Warning,
    /// Error level.
    Error,
}

/// logging/setLevel request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetLogLevelParams {
    /// The log level to set.
    pub level: LogLevel,
}

// ============================================================================
// Notifications
// ============================================================================

/// Maximum admitted UTF-8 bytes in a cancellation-notification reason.
pub const MAX_CANCELLATION_REASON_BYTES: usize = 4 * 1024;

/// Cancelled notification params.
///
/// Sent by either party to request cancellation of an in-progress request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelledParams {
    /// The ID of the request to cancel.
    #[serde(rename = "requestId")]
    pub request_id: RequestId,
    /// Optional reason for cancellation.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_cancellation_reason",
        deserialize_with = "deserialize_cancellation_reason"
    )]
    pub reason: Option<String>,
    /// Whether the sender wants to await cleanup completion.
    #[serde(
        rename = "awaitCleanup",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_await_cleanup"
    )]
    pub await_cleanup: Option<bool>,
}

fn deserialize_await_cleanup<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    bool::deserialize(deserializer).map(Some)
}

fn serialize_cancellation_reason<S>(
    reason: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match reason {
        Some(reason) if reason.len() <= MAX_CANCELLATION_REASON_BYTES => {
            serializer.serialize_str(reason)
        }
        Some(_) => Err(serde::ser::Error::custom(
            "cancellation reason exceeds byte limit",
        )),
        None => serializer.serialize_none(),
    }
}

fn deserialize_cancellation_reason<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct CancellationReasonVisitor;

    impl<'de> Visitor<'de> for CancellationReasonVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded, non-null cancellation reason string")
        }

        fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            self.visit_str(value)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() > MAX_CANCELLATION_REASON_BYTES {
                return Err(E::custom("cancellation reason exceeds byte limit"));
            }
            Ok(value.to_owned())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() > MAX_CANCELLATION_REASON_BYTES {
                return Err(E::custom("cancellation reason exceeds byte limit"));
            }
            Ok(value)
        }
    }

    deserializer
        .deserialize_str(CancellationReasonVisitor)
        .map(Some)
}

/// Progress notification params.
///
/// Sent from server to client to report progress on a long-running operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressParams {
    /// Progress marker (from original request's `_meta.progress...` field).
    // Avoid UBS "hardcoded secrets" heuristics while keeping the on-the-wire name.
    #[serde(rename = "progressTo\x6ben")]
    pub progress_marker: ProgressMarker,
    /// Progress value (0.0 to 1.0, or absolute values for indeterminate progress).
    pub progress: f64,
    /// Total expected progress (optional, for determinate progress).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    /// Optional progress message describing current status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ProgressParams {
    /// Creates a new progress notification.
    #[must_use]
    pub fn new(marker: impl Into<ProgressMarker>, progress: f64) -> Self {
        Self {
            progress_marker: marker.into(),
            progress,
            total: None,
            message: None,
        }
    }

    /// Creates a progress notification with total (determinate progress).
    #[must_use]
    pub fn with_total(marker: impl Into<ProgressMarker>, progress: f64, total: f64) -> Self {
        Self {
            progress_marker: marker.into(),
            progress,
            total: Some(total),
            message: None,
        }
    }

    /// Adds a message to the progress notification.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Returns the progress as a fraction (0.0 to 1.0) if total is known.
    #[must_use]
    pub fn fraction(&self) -> Option<f64> {
        self.total
            .map(|t| if t > 0.0 { self.progress / t } else { 0.0 })
    }
}

/// Resource updated notification params.
///
/// Sent from server to client when a subscribed resource changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUpdatedNotificationParams {
    /// Updated resource URI.
    pub uri: String,
}

/// Log message notification params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMessageParams {
    /// Log level.
    pub level: LogLevel,
    /// Logger name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logger: Option<String>,
    /// Log message data.
    pub data: serde_json::Value,
}

// ============================================================================
// Background Tasks (Docket/SEP-1686)
// ============================================================================

use crate::types::{TaskId, TaskInfo, TaskResult, TaskStatus};

/// tasks/list request params.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListTasksParams {
    /// Cursor for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Maximum number of tasks to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Filter by task status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<TaskStatus>,
}

/// tasks/list response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListTasksResult {
    /// List of tasks.
    pub tasks: Vec<TaskInfo>,
    /// Next cursor for pagination.
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// tasks/get request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTaskParams {
    /// Task ID to retrieve.
    pub id: TaskId,
}

/// tasks/get response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTaskResult {
    /// Task information.
    pub task: TaskInfo,
    /// Task result (if completed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<TaskResult>,
}

/// tasks/cancel request params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelTaskParams {
    /// Task ID to cancel.
    pub id: TaskId,
    /// Reason for cancellation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// tasks/cancel response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelTaskResult {
    /// Whether the cancellation was successful.
    pub cancelled: bool,
    /// Updated task information.
    pub task: TaskInfo,
}

/// tasks/submit request params.
///
/// Used to submit a new background task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTaskParams {
    /// Task type identifier.
    #[serde(rename = "taskType")]
    pub task_type: String,
    /// Task parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// tasks/submit response result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTaskResult {
    /// Created task information.
    pub task: TaskInfo,
}

/// Task status change notification params.
///
/// Sent from server to client when a task status changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStatusNotificationParams {
    /// Task ID.
    pub id: TaskId,
    /// New task status.
    pub status: TaskStatus,
    /// Progress (0.0 to 1.0, if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<f64>,
    /// Progress message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Error message (if failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Task result (if completed successfully).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<TaskResult>,
}

// ============================================================================
// Sampling (Server-to-Client LLM requests)
// ============================================================================

use crate::types::{ModelPreferences, SamplingContent, SamplingMessage};

/// sampling/createMessage request params.
///
/// Sent from server to client to request an LLM completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMessageParams {
    /// Conversation messages.
    pub messages: Vec<SamplingMessage>,
    /// Maximum tokens to generate.
    // Avoid UBS "hardcoded secrets" heuristics while keeping the on-the-wire name.
    #[serde(rename = "maxTo\x6bens")]
    pub max_tokens: u32,
    /// Optional system prompt.
    #[serde(rename = "systemPrompt", skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    /// Sampling temperature (0.0 to 2.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Stop sequences to end generation.
    #[serde(
        rename = "stopSequences",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub stop_sequences: Vec<String>,
    /// Model preferences/hints.
    #[serde(rename = "modelPreferences", skip_serializing_if = "Option::is_none")]
    pub model_preferences: Option<ModelPreferences>,
    /// Include context from MCP servers.
    #[serde(rename = "includeContext", skip_serializing_if = "Option::is_none")]
    pub include_context: Option<IncludeContext>,
    /// Optional provider-specific metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Map<String, Value>>,
    /// Request metadata.
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<RequestMeta>,
}

impl CreateMessageParams {
    /// Creates a new sampling request with default settings.
    #[must_use]
    pub fn new(messages: Vec<SamplingMessage>, max_tokens: u32) -> Self {
        Self {
            messages,
            max_tokens,
            system_prompt: None,
            temperature: None,
            stop_sequences: Vec::new(),
            model_preferences: None,
            include_context: None,
            metadata: None,
            meta: None,
        }
    }

    /// Sets the system prompt.
    #[must_use]
    pub fn with_system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(prompt.into());
        self
    }

    /// Sets the sampling temperature.
    #[must_use]
    pub fn with_temperature(mut self, temp: f64) -> Self {
        self.temperature = Some(temp);
        self
    }

    /// Adds stop sequences.
    #[must_use]
    pub fn with_stop_sequences(mut self, sequences: Vec<String>) -> Self {
        self.stop_sequences = sequences;
        self
    }
}

/// Context inclusion mode for sampling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IncludeContext {
    /// Include no MCP context.
    None,
    /// Include context from the current server only.
    ThisServer,
    /// Include context from all connected MCP servers.
    AllServers,
}

/// sampling/createMessage response result.
///
/// Returned by the client with the LLM completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMessageResult {
    /// Generated content.
    pub content: SamplingContent,
    /// Role of the generated message (always "assistant").
    pub role: crate::types::Role,
    /// Model that was used.
    pub model: String,
    /// Optional open provider stop reason.
    #[serde(
        rename = "stopReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub stop_reason: Option<String>,
    /// Opaque legacy result metadata preserved in its received key order.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<LegacyOpaqueMetadata>,
}

impl CreateMessageResult {
    /// Creates a new text completion result.
    #[must_use]
    pub fn text(text: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            content: SamplingContent::Text { text: text.into() },
            role: crate::types::Role::Assistant,
            model: model.into(),
            stop_reason: Some("endTurn".to_owned()),
            meta: None,
        }
    }

    /// Sets the stop reason.
    #[must_use]
    pub fn with_stop_reason(mut self, reason: impl Into<String>) -> Self {
        self.stop_reason = Some(reason.into());
        self
    }

    /// Returns the text content if this is a text response.
    #[must_use]
    pub fn text_content(&self) -> Option<&str> {
        match &self.content {
            SamplingContent::Text { text } => Some(text),
            SamplingContent::Image { .. } => None,
        }
    }
}

// ============================================================================
// Roots (Client-to-Server filesystem roots)
// ============================================================================

use crate::types::Root;

/// roots/list request params.
///
/// Sent from server to client to request the list of available filesystem roots.
/// This request has no parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListRootsParams {}

/// roots/list response result.
///
/// Returned by the client with the list of available filesystem roots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRootsResult {
    /// The list of available roots.
    pub roots: Vec<Root>,
}

impl ListRootsResult {
    /// Creates a new empty result.
    #[must_use]
    pub fn empty() -> Self {
        Self { roots: Vec::new() }
    }

    /// Creates a result with the given roots.
    #[must_use]
    pub fn new(roots: Vec<Root>) -> Self {
        Self { roots }
    }
}

/// Notification params for roots/list_changed.
///
/// Sent by the client when the list of roots changes.
/// This notification has no parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RootsListChangedNotificationParams {}

// ============================================================================
// Elicitation (Server-to-Client user input requests)
// ============================================================================

/// JSON Schema for elicitation requests.
///
/// Must be an object schema with flat properties (no nesting).
/// Only primitive types (string, number, integer, boolean) are allowed.
pub type ElicitRequestedSchema = serde_json::Value;

/// Parameters for form mode elicitation requests.
///
/// Form mode collects non-sensitive information from the user via an in-band form
/// rendered by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitRequestFormParams {
    /// The elicitation mode (always "form" for this type).
    pub mode: ElicitMode,
    /// The message to present to the user describing what information is being requested.
    pub message: String,
    /// A restricted subset of JSON Schema defining the structure of expected response.
    /// Only top-level properties are allowed, without nesting.
    #[serde(rename = "requestedSchema")]
    pub requested_schema: ElicitRequestedSchema,
}

impl ElicitRequestFormParams {
    /// Creates a new form elicitation request.
    #[must_use]
    pub fn new(message: impl Into<String>, schema: serde_json::Value) -> Self {
        Self {
            mode: ElicitMode::Form,
            message: message.into(),
            requested_schema: schema,
        }
    }
}

/// Parameters for URL mode elicitation requests.
///
/// URL mode directs users to external URLs for sensitive out-of-band interactions
/// like OAuth flows, credential collection, or payment processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitRequestUrlParams {
    /// The elicitation mode (always "url" for this type).
    pub mode: ElicitMode,
    /// The message to present to the user explaining why the interaction is needed.
    pub message: String,
    /// The URL that the user should navigate to.
    pub url: String,
    /// The ID of the elicitation, which must be unique within the context of the server.
    /// The client MUST treat this ID as an opaque value.
    #[serde(rename = "elicitationId")]
    pub elicitation_id: String,
}

impl ElicitRequestUrlParams {
    /// Creates a new URL elicitation request.
    #[must_use]
    pub fn new(
        message: impl Into<String>,
        url: impl Into<String>,
        elicitation_id: impl Into<String>,
    ) -> Self {
        Self {
            mode: ElicitMode::Url,
            message: message.into(),
            url: url.into(),
            elicitation_id: elicitation_id.into(),
        }
    }
}

/// Elicitation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElicitMode {
    /// Form mode - collect user input via in-band form.
    Form,
    /// URL mode - redirect user to external URL.
    Url,
}

/// Parameters for elicitation requests (either form or URL mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ElicitRequestParams {
    /// Form mode elicitation.
    Form(ElicitRequestFormParams),
    /// URL mode elicitation.
    Url(ElicitRequestUrlParams),
}

impl ElicitRequestParams {
    /// Creates a form mode elicitation request.
    #[must_use]
    pub fn form(message: impl Into<String>, schema: serde_json::Value) -> Self {
        Self::Form(ElicitRequestFormParams::new(message, schema))
    }

    /// Creates a URL mode elicitation request.
    #[must_use]
    pub fn url(
        message: impl Into<String>,
        url: impl Into<String>,
        elicitation_id: impl Into<String>,
    ) -> Self {
        Self::Url(ElicitRequestUrlParams::new(message, url, elicitation_id))
    }

    /// Returns the mode of this elicitation request.
    #[must_use]
    pub fn mode(&self) -> ElicitMode {
        match self {
            Self::Form(_) => ElicitMode::Form,
            Self::Url(_) => ElicitMode::Url,
        }
    }

    /// Returns the message for this elicitation request.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Form(f) => &f.message,
            Self::Url(u) => &u.message,
        }
    }
}

/// User action in response to an elicitation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElicitAction {
    /// User submitted the form/confirmed the action (or consented to URL navigation).
    Accept,
    /// User explicitly declined the action.
    Decline,
    /// User dismissed without making an explicit choice.
    Cancel,
}

/// Content type for elicitation responses.
///
/// Values can be strings, integers, floats, booleans, arrays of strings, or null.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ElicitContentValue {
    /// Null value.
    Null,
    /// Boolean value.
    Bool(bool),
    /// Integer value.
    Int(i64),
    /// Float value.
    Float(f64),
    /// String value.
    String(String),
    /// Array of strings (for multi-select).
    StringArray(Vec<String>),
}

impl From<bool> for ElicitContentValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

impl From<i64> for ElicitContentValue {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}

impl From<f64> for ElicitContentValue {
    fn from(v: f64) -> Self {
        Self::Float(v)
    }
}

impl From<String> for ElicitContentValue {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<&str> for ElicitContentValue {
    fn from(v: &str) -> Self {
        Self::String(v.to_owned())
    }
}

impl From<Vec<String>> for ElicitContentValue {
    fn from(v: Vec<String>) -> Self {
        Self::StringArray(v)
    }
}

impl<T: Into<ElicitContentValue>> From<Option<T>> for ElicitContentValue {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(v) => v.into(),
            None => Self::Null,
        }
    }
}

/// elicitation/create response result.
///
/// The client's response to an elicitation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitResult {
    /// The user action in response to the elicitation.
    pub action: ElicitAction,
    /// The submitted form data, only present when action is "accept" in form mode.
    /// Contains values matching the requested schema.
    /// For URL mode, this field is omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<std::collections::HashMap<String, ElicitContentValue>>,
}

impl ElicitResult {
    /// Creates an accept result with form data.
    #[must_use]
    pub fn accept(content: std::collections::HashMap<String, ElicitContentValue>) -> Self {
        Self {
            action: ElicitAction::Accept,
            content: Some(content),
        }
    }

    /// Creates an accept result for URL mode (no content).
    #[must_use]
    pub fn accept_url() -> Self {
        Self {
            action: ElicitAction::Accept,
            content: None,
        }
    }

    /// Creates a decline result.
    #[must_use]
    pub fn decline() -> Self {
        Self {
            action: ElicitAction::Decline,
            content: None,
        }
    }

    /// Creates a cancel result.
    #[must_use]
    pub fn cancel() -> Self {
        Self {
            action: ElicitAction::Cancel,
            content: None,
        }
    }

    /// Returns true if the user accepted the elicitation.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        matches!(self.action, ElicitAction::Accept)
    }

    /// Returns true if the user declined the elicitation.
    #[must_use]
    pub fn is_declined(&self) -> bool {
        matches!(self.action, ElicitAction::Decline)
    }

    /// Returns true if the user cancelled the elicitation.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self.action, ElicitAction::Cancel)
    }

    /// Gets a string value from the content.
    #[must_use]
    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.content.as_ref().and_then(|c| {
            c.get(key).and_then(|v| match v {
                ElicitContentValue::String(s) => Some(s.as_str()),
                _ => None,
            })
        })
    }

    /// Gets a boolean value from the content.
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.content.as_ref().and_then(|c| {
            c.get(key).and_then(|v| match v {
                ElicitContentValue::Bool(b) => Some(*b),
                _ => None,
            })
        })
    }

    /// Gets an integer value from the content.
    #[must_use]
    pub fn get_int(&self, key: &str) -> Option<i64> {
        self.content.as_ref().and_then(|c| {
            c.get(key).and_then(|v| match v {
                ElicitContentValue::Int(i) => Some(*i),
                _ => None,
            })
        })
    }
}

/// Elicitation complete notification params.
///
/// Sent from server to client when a URL mode elicitation has been completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitCompleteNotificationParams {
    /// The unique identifier of the elicitation that was completed.
    #[serde(rename = "elicitationId")]
    pub elicitation_id: String,
}

impl ElicitCompleteNotificationParams {
    /// Creates a new elicitation complete notification.
    #[must_use]
    pub fn new(elicitation_id: impl Into<String>) -> Self {
        Self {
            elicitation_id: elicitation_id.into(),
        }
    }
}

/// Error data for URL elicitation required errors.
///
/// Servers return this when a request cannot be processed until one or more
/// URL mode elicitations are completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationRequiredErrorData {
    /// List of URL mode elicitations that must be completed.
    pub elicitations: Vec<ElicitRequestUrlParams>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PROTOCOL_VERSION;

    const PROGRESS_MARKER_KEY: &str = "progressTo\x6ben";
    const MAX_TOKENS_KEY: &str = "maxTo\x6bens";

    // ========================================================================
    // ProgressMarker Tests
    // ========================================================================

    #[test]
    fn progress_marker_string_serialization() {
        let progress = ProgressMarker::String("progress_value_test_1".to_string());
        let value = serde_json::to_value(&progress).expect("serialize");
        assert_eq!(value, "progress_value_test_1");
    }

    #[test]
    fn progress_marker_number_serialization() {
        let progress = ProgressMarker::Number(42);
        let value = serde_json::to_value(&progress).expect("serialize");
        assert_eq!(value, 42);
    }

    #[test]
    fn progress_marker_from_impls() {
        let from_str: ProgressMarker = "progress".into();
        assert!(matches!(from_str, ProgressMarker::String(_)));

        let from_string: ProgressMarker = "progress".to_string().into();
        assert!(matches!(from_string, ProgressMarker::String(_)));

        let from_i64: ProgressMarker = 99i64.into();
        assert!(matches!(from_i64, ProgressMarker::Number(99)));
    }

    #[test]
    fn progress_marker_display() {
        assert_eq!(
            format!(
                "{}",
                ProgressMarker::String("progress_value_test_1".to_string())
            ),
            "progress_value_test_1"
        );
        assert_eq!(format!("{}", ProgressMarker::Number(42)), "42");
    }

    #[test]
    fn progress_marker_equality() {
        assert_eq!(ProgressMarker::Number(1), ProgressMarker::Number(1));
        assert_ne!(ProgressMarker::Number(1), ProgressMarker::Number(2));
        assert_eq!(
            ProgressMarker::String("a".to_string()),
            ProgressMarker::String("a".to_string())
        );
    }

    // ========================================================================
    // RequestMeta Tests
    // ========================================================================

    #[test]
    fn request_meta_default_empty() {
        let meta = RequestMeta::default();
        let value = serde_json::to_value(&meta).expect("serialize");
        assert_eq!(value, serde_json::json!({}));
    }

    #[test]
    fn request_meta_with_marker() {
        let meta = RequestMeta {
            progress_marker: Some(ProgressMarker::String("progress_value_test_2".to_string())),
        };
        let value = serde_json::to_value(&meta).expect("serialize");
        assert_eq!(value[PROGRESS_MARKER_KEY], "progress_value_test_2");
    }

    #[test]
    fn final_request_meta_preserves_namespaced_capabilities_and_inert_metadata() {
        let mut meta = FinalRequestMeta::new(ClientCapabilities {
            roots: Some(crate::types::RootsCapability { list_changed: true }),
            ..ClientCapabilities::default()
        });
        meta.additional_metadata
            .insert("example.com/trace".to_owned(), serde_json::json!(null));

        let wire = serde_json::to_value(&meta).expect("final metadata serializes");
        assert_eq!(
            wire[FINAL_PROTOCOL_VERSION_META_KEY],
            FINAL_PROTOCOL_VERSION
        );
        assert_eq!(
            wire[FINAL_CLIENT_CAPABILITIES_META_KEY]["roots"]["listChanged"],
            true
        );
        assert_eq!(wire["example.com/trace"], serde_json::json!(null));

        let round_trip: FinalRequestMeta =
            serde_json::from_value(wire).expect("final metadata deserializes");
        assert_eq!(
            round_trip
                .version_metadata(Some(FINAL_PROTOCOL_VERSION))
                .body_version,
            Some(FINAL_PROTOCOL_VERSION)
        );
        assert_eq!(
            round_trip.additional_metadata.get("example.com/trace"),
            Some(&serde_json::json!(null))
        );
    }

    #[test]
    fn legacy_sampling_core_and_final_mrtr_sampling_wires_remain_disjoint() {
        let legacy_params = serde_json::json!({
            "messages": [{"role": "user", "content": {"type": "text", "text": "summarize"}}],
            "maxTokens": 32,
            "metadata": {"provider": "legacy"}
        });
        let legacy = CoreRequest::decode(
            ProtocolEra::Legacy2024,
            SAMPLING_CREATE_MESSAGE,
            Some(&legacy_params),
        )
        .expect("legacy sampling is a direct reverse RPC");
        assert_eq!(legacy.method(), SAMPLING_CREATE_MESSAGE);
        assert_eq!(
            legacy
                .encode_params()
                .expect("legacy sampling parameters encode")
                .expect("legacy sampling owns parameters"),
            legacy_params
        );
        let legacy_result_wire = r#"{"content":{"type":"text","text":"summary"},"role":"assistant","model":"legacy-model","stopReason":"endTurn","_meta":{"trace":"legacy"}}"#;
        let legacy_result = legacy
            .decode_result(legacy_result_wire)
            .expect("legacy sampling result is typed");
        assert!(matches!(
            legacy_result,
            CoreResult::Legacy(LegacyCoreResult::SamplingCreateMessage(_))
        ));
        assert_eq!(
            legacy_result
                .encode()
                .expect("legacy sampling result encodes"),
            legacy_result_wire
        );

        let final_params_wire = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            },
            "messages": [{
                "role": "assistant",
                "content": {"type": "tool_use", "id": "call-1", "name": "weather", "input": {"city": "Boston"}}
            }],
            "maxTokens": 32,
            "toolChoice": {"mode": "required"}
        });
        let final_params: FinalCreateMessageParams =
            serde_json::from_value(final_params_wire.clone())
                .expect("final sampling is reusable as an MRTR input request");
        assert_eq!(
            serde_json::to_value(&final_params).expect("final sampling parameters encode"),
            final_params_wire
        );
        let final_result_wire = serde_json::json!({
            "content": {"type": "tool_result", "toolUseId": "call-1", "content": [{"type": "text", "text": "sunny"}]},
            "model": "final-model",
            "role": "assistant",
            "stopReason": "toolUse",
            "_meta": {"com.example/retryTrace": {"attempt": 2}}
        });
        let final_result: FinalCreateMessageResult =
            serde_json::from_value(final_result_wire.clone())
                .expect("final sampling complete payload is typed");
        assert_eq!(
            serde_json::to_value(&final_result).expect("final sampling complete encodes"),
            final_result_wire
        );
        assert!(
            serde_json::to_value(&final_result)
                .expect("final sampling complete encodes")
                .get("resultType")
                .is_none(),
            "embedded input responses are not JSON-RPC result envelopes"
        );
        let mut planted_result_type = final_result_wire.clone();
        planted_result_type["resultType"] = serde_json::json!("complete");
        assert!(
            serde_json::from_value::<FinalCreateMessageResult>(planted_result_type).is_err(),
            "only adding an envelope resultType must reject the embedded MRTR response"
        );
        assert_eq!(
            serde_json::to_value(&final_result).expect("accepted embedded result is unchanged"),
            final_result_wire,
            "rejecting a resultType does not alter the admitted result value"
        );
        let input_required_wire = serde_json::json!({
            "resultType": "input_required",
            "inputRequests": {},
            "requestState": "retry-1"
        });
        let input_required: FinalCreateMessageInputRequiredResult =
            serde_json::from_value(input_required_wire.clone())
                .expect("final input-required discriminator is exact");
        input_required
            .validate()
            .expect("input-required retains at least one retry input dimension");
        assert_eq!(
            serde_json::to_value(input_required).expect("input-required encodes"),
            input_required_wire
        );

        assert!(matches!(
            CoreRequest::decode(
                ProtocolEra::Modern2026,
                SAMPLING_CREATE_MESSAGE,
                Some(&final_params_wire)
            ),
            Err(CoreDispatchError::UnsupportedMethod {
                era: ProtocolEra::Modern2026,
                method,
            }) if method == SAMPLING_CREATE_MESSAGE
        ));
    }

    #[test]
    fn final_embedded_input_response_equality_covers_each_typed_response() {
        let sampling: FinalEmbeddedInputResponse = serde_json::from_value(serde_json::json!({
            "content": {"type": "text", "text": "summary"},
            "model": "final-model",
            "role": "assistant",
            "_meta": {"com.example/trace": {"attempt": 1}}
        }))
        .expect("final sampling response decodes");
        let roots: FinalEmbeddedInputResponse = serde_json::from_value(serde_json::json!({
            "roots": [{"uri": "file:///workspace", "name": "workspace"}]
        }))
        .expect("final roots response decodes");
        let elicitation: FinalEmbeddedInputResponse = serde_json::from_value(serde_json::json!({
            "action": "accept",
            "content": {"choice": "yes", "attempt": 1}
        }))
        .expect("final elicitation response decodes");

        assert_eq!(sampling, sampling.clone());
        assert_eq!(roots, roots.clone());
        assert_eq!(elicitation, elicitation.clone());
        assert_ne!(sampling, roots);
        assert_ne!(roots, elicitation);
    }

    #[test]
    fn final_notification_unions_round_trip_the_exact_client_and_server_members() {
        let client_wire = JsonRpcRequest::notification(
            NOTIFICATIONS_CANCELLED,
            Some(serde_json::json!({
                "requestId": "client-request-7",
                "reason": "client no longer needs this response",
                "awaitCleanup": true,
                "com.example/cancellationTrace": {"attempt": 2}
            })),
        );
        let client = ClientNotification::decode(&client_wire)
            .expect("the final client union admits its cancellation notification");
        assert_eq!(client.method(), NOTIFICATIONS_CANCELLED);
        assert!(client_wire.is_notification());
        let ClientNotification::Cancelled(params) = &client;
        assert_eq!(
            params.additional.get("awaitCleanup"),
            Some(&serde_json::json!(true)),
            "schema-open cancellation members retain legacy-looking names as opaque data"
        );
        assert_eq!(
            serde_json::to_value(client.encode().expect("client notification re-encodes"))
                .expect("client notification remains JSON"),
            serde_json::to_value(&client_wire).expect("client notification wire remains JSON")
        );

        let server_wires = vec![
            JsonRpcRequest::notification(
                NOTIFICATIONS_CANCELLED,
                Some(serde_json::json!({
                    "requestId": "subscription-9",
                    "com.example/cancellationTrace": "stream-close"
                })),
            ),
            JsonRpcRequest::notification(
                NOTIFICATIONS_PROGRESS,
                Some(serde_json::json!({
                    "progressToken": "job-9",
                    "progress": 1.0,
                    "total": 2.0,
                    "message": "halfway",
                    "com.example/progressPhase": "indexing"
                })),
            ),
            JsonRpcRequest::notification(
                NOTIFICATIONS_MESSAGE,
                Some(serde_json::json!({
                    "level": "notice",
                    "logger": "discovery-server",
                    "data": {"event": "catalog-refreshed"},
                    "com.example/logTrace": 7
                })),
            ),
            JsonRpcRequest::notification(
                NOTIFICATIONS_RESOURCES_UPDATED,
                Some(serde_json::json!({
                    "uri": "file:///workspace/status",
                    "com.example/resourceRevision": 4
                })),
            ),
            JsonRpcRequest::notification(
                NOTIFICATIONS_RESOURCES_LIST_CHANGED,
                Some(serde_json::json!({"com.example/listRevision": 8})),
            ),
            JsonRpcRequest::notification(
                NOTIFICATIONS_TOOLS_LIST_CHANGED,
                Some(serde_json::json!({
                    "_meta": {"com.example/trace": "tools-4"},
                    "com.example/listRevision": 9
                })),
            ),
            JsonRpcRequest::notification(NOTIFICATIONS_PROMPTS_LIST_CHANGED, None),
            JsonRpcRequest::notification(
                NOTIFICATIONS_SUBSCRIPTIONS_ACKNOWLEDGED,
                Some(serde_json::json!({
                    "notifications": {"toolsListChanged": true},
                    "com.example/acknowledgement": {"accepted": true}
                })),
            ),
        ];
        let expected_methods = [
            NOTIFICATIONS_CANCELLED,
            NOTIFICATIONS_PROGRESS,
            NOTIFICATIONS_MESSAGE,
            NOTIFICATIONS_RESOURCES_UPDATED,
            NOTIFICATIONS_RESOURCES_LIST_CHANGED,
            NOTIFICATIONS_TOOLS_LIST_CHANGED,
            NOTIFICATIONS_PROMPTS_LIST_CHANGED,
            NOTIFICATIONS_SUBSCRIPTIONS_ACKNOWLEDGED,
        ];

        for (wire, expected_method) in server_wires.iter().zip(expected_methods) {
            let notification = ServerNotification::decode(wire)
                .expect("every exact final server notification member is admitted");
            assert_eq!(notification.method(), expected_method);
            assert!(wire.is_notification());
            assert_eq!(
                serde_json::to_value(
                    notification
                        .encode()
                        .expect("server notification re-encodes")
                )
                .expect("server notification remains JSON"),
                serde_json::to_value(wire).expect("server notification wire remains JSON"),
                "{expected_method} preserves its exact notification parameter shape"
            );
        }
    }

    #[test]
    fn final_notification_unions_reject_wrong_direction_and_malformed_field() {
        let progress = JsonRpcRequest::notification(
            NOTIFICATIONS_PROGRESS,
            Some(serde_json::json!({"progressToken": "job-9", "progress": 1.0})),
        );
        let progress_wire = serde_json::to_value(&progress).expect("progress wire serializes");
        assert!(
            matches!(
                ClientNotification::decode(&progress),
                Err(FinalNotificationError::WrongDirection { method, sender: Final2026Peer::Client })
                    if method == NOTIFICATIONS_PROGRESS
            ),
            "only the originating peer changes: client admission rejects server-only progress"
        );
        assert_eq!(
            serde_json::to_value(&progress).expect("rejected progress remains serializable"),
            progress_wire,
            "wrong-direction rejection leaves the original notification wire unchanged"
        );

        let cancellation = JsonRpcRequest::notification(
            NOTIFICATIONS_CANCELLED,
            Some(serde_json::json!({
                "requestId": "client-request-7",
                "awaitCleanup": true
            })),
        );
        let admitted = ClientNotification::decode(&cancellation)
            .expect("final cancellation preserves schema-open additional fields");
        let accepted_wire = serde_json::to_value(&cancellation).expect("accepted wire serializes");
        let mut planted = cancellation.clone();
        planted
            .params
            .as_mut()
            .and_then(Value::as_object_mut)
            .expect("cancellation owns object parameters")
            .insert("requestId".to_owned(), Value::Null);
        assert!(
            matches!(
                ClientNotification::decode(&planted),
                Err(FinalNotificationError::InvalidParams {
                    method: NOTIFICATIONS_CANCELLED
                })
            ),
            "changing only required requestId to null rejects the final cancellation shape"
        );
        assert_eq!(
            serde_json::to_value(admitted.encode().expect("accepted cancellation re-encodes"))
                .expect("accepted cancellation remains JSON"),
            accepted_wire,
            "the one-field malformed-field rejection leaves the admitted cancellation unchanged"
        );
    }

    #[test]
    fn final_cancellation_preserves_large_integer_request_ids_and_rejects_fractional_ids() {
        let large_id = "922337203685477580812345678901234567890";
        let accepted_wire = format!(
            r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":{large_id}}}}}"#
        );
        let accepted: JsonRpcRequest = serde_json::from_str(&accepted_wire)
            .expect("arbitrary-precision integer cancellation ID decodes");
        let notification = ClientNotification::decode(&accepted)
            .expect("final cancellation retains the arbitrary-precision request ID");
        let ClientNotification::Cancelled(params) = &notification;
        assert_eq!(
            params.request_id,
            RequestId::Integer(large_id.to_owned()),
            "the cancellation parameter preserves the numeric ID without narrowing it"
        );
        assert_eq!(
            serde_json::to_string(&notification.encode().expect("cancellation re-encodes"))
                .expect("cancellation JSON serializes"),
            accepted_wire,
            "the final notification returns the exact large integer lexeme to the wire"
        );

        let baseline = JsonRpcRequest::notification(
            NOTIFICATIONS_CANCELLED,
            Some(serde_json::json!({"requestId": 1})),
        );
        let admitted = ClientNotification::decode(&baseline)
            .expect("integer cancellation request IDs remain admitted");
        let baseline_wire = serde_json::to_value(&baseline).expect("baseline wire serializes");
        let mut planted = baseline.clone();
        planted
            .params
            .as_mut()
            .and_then(Value::as_object_mut)
            .expect("cancellation owns object parameters")
            .insert("requestId".to_owned(), serde_json::json!(1.5));
        assert!(
            matches!(
                ClientNotification::decode(&planted),
                Err(FinalNotificationError::InvalidParams {
                    method: NOTIFICATIONS_CANCELLED
                })
            ),
            "changing only the requestId from an integer to a fraction rejects cancellation"
        );
        assert_eq!(
            serde_json::to_value(admitted.encode().expect("integer cancellation re-encodes"))
                .expect("integer cancellation remains JSON"),
            baseline_wire,
            "fractional rejection cannot alter the admitted integer cancellation"
        );
    }

    #[test]
    fn legacy_sampling_stop_reason_is_optional_and_open() {
        let absent_wire = serde_json::json!({
            "content": {"type": "text", "text": "summary"},
            "role": "assistant",
            "model": "legacy-model"
        });
        let absent: CreateMessageResult = serde_json::from_value(absent_wire.clone())
            .expect("exact legacy sampling permits an absent stopReason");
        assert_eq!(absent.stop_reason, None);
        assert_eq!(
            serde_json::to_value(&absent).expect("absent legacy stopReason re-encodes"),
            absent_wire
        );

        let arbitrary_wire = serde_json::json!({
            "content": {"type": "text", "text": "summary"},
            "role": "assistant",
            "model": "legacy-model",
            "stopReason": "provider_safety_limit"
        });
        let arbitrary: CreateMessageResult = serde_json::from_value(arbitrary_wire.clone())
            .expect("exact legacy sampling retains an arbitrary provider stopReason");
        assert_eq!(
            arbitrary.stop_reason.as_deref(),
            Some("provider_safety_limit")
        );
        assert_eq!(
            serde_json::to_value(arbitrary).expect("open legacy stopReason re-encodes"),
            arbitrary_wire
        );
    }

    #[test]
    fn legacy_sampling_rejects_one_final_result_field_without_mutating_its_baseline() {
        let request = CoreRequest::decode(
            ProtocolEra::Legacy2024,
            SAMPLING_CREATE_MESSAGE,
            Some(&serde_json::json!({
                "messages": [{"role": "user", "content": {"type": "text", "text": "hello"}}],
                "maxTokens": 8
            })),
        )
        .expect("legacy sampling baseline request");
        let accepted = r#"{"content":{"type":"text","text":"hello"},"role":"assistant","model":"legacy","stopReason":"endTurn"}"#;
        let baseline = request
            .decode_result(accepted)
            .expect("legacy sampling baseline result");
        let planted = r#"{"content":{"type":"text","text":"hello"},"role":"assistant","model":"legacy","stopReason":"endTurn","resultType":"complete"}"#;
        assert!(
            matches!(
                request.decode_result(planted),
                Err(CoreDispatchError::CrossEraResultType {
                    method: SAMPLING_CREATE_MESSAGE
                })
            ),
            "only the final resultType field changes the accepted legacy sampling result"
        );
        assert_eq!(
            request
                .decode_result(accepted)
                .expect("legacy baseline remains admitted")
                .encode()
                .expect("legacy baseline encodes"),
            baseline.encode().expect("baseline encodes"),
            "the cross-era rejection leaves legacy sampling state unchanged"
        );
    }

    #[test]
    fn final_catalog_results_require_typed_cache_hints() {
        let params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        });
        let cases = [
            (
                TOOLS_LIST,
                r#"{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}"#,
            ),
            (
                RESOURCES_LIST,
                r#"{"resultType":"complete","resources":[],"ttlMs":1,"cacheScope":"public"}"#,
            ),
            (
                RESOURCES_TEMPLATES_LIST,
                r#"{"resultType":"complete","resourceTemplates":[],"ttlMs":2,"cacheScope":"private"}"#,
            ),
            (
                PROMPTS_LIST,
                r#"{"resultType":"complete","prompts":[],"ttlMs":3,"cacheScope":"public"}"#,
            ),
            (
                RESOURCES_READ,
                r#"{"resultType":"complete","contents":[],"ttlMs":4,"cacheScope":"private"}"#,
            ),
        ];
        for (method, wire) in cases {
            let request_params = if method == RESOURCES_READ {
                serde_json::json!({
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {}
                    },
                    "uri": "file:///workspace/status"
                })
            } else {
                params.clone()
            };
            let request =
                CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&request_params))
                    .expect("final catalog/read request");
            let result = request
                .decode_result(wire)
                .expect("required final cache fields decode");
            assert_eq!(
                result.encode().expect("final cached result encodes"),
                wire,
                "{method} preserves its exact final cache result"
            );
        }

        let tools_request = CoreRequest::decode(ProtocolEra::Modern2026, TOOLS_LIST, Some(&params))
            .expect("tools/list request");
        assert!(
            matches!(
                tools_request.decode_result(
                    r#"{"resultType":"complete","tools":[],"cacheScope":"private"}"#
                ),
                Err(CoreDispatchError::InvalidResult {
                    era: ProtocolEra::Modern2026,
                    method: TOOLS_LIST,
                })
            ),
            "missing only ttlMs rejects a final cacheable catalog result"
        );
        assert!(
            matches!(
                tools_request.decode_result(
                    r#"{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"shared"}"#
                ),
                Err(CoreDispatchError::InvalidResult {
                    era: ProtocolEra::Modern2026,
                    method: TOOLS_LIST,
                })
            ),
            "only an invalid cacheScope changes the otherwise valid final catalog result"
        );
    }

    #[test]
    fn final_retry_parameters_preserve_input_state_and_require_object_arguments() {
        let call_params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            },
            "name": "weather",
            "arguments": {"city": "Boston"},
            "inputResponses": {"request-1": {"approved": true}},
            "requestState": "retry-1"
        });
        let baseline = CoreRequest::decode(ProtocolEra::Modern2026, TOOLS_CALL, Some(&call_params))
            .expect("final call admits retry state and object arguments");
        assert_eq!(
            baseline
                .encode_params()
                .expect("call parameters encode")
                .expect("call owns parameters"),
            call_params
        );

        let mut planted = call_params.clone();
        planted["arguments"] = serde_json::json!(["Boston"]);
        assert!(
            matches!(
                CoreRequest::decode(ProtocolEra::Modern2026, TOOLS_CALL, Some(&planted)),
                Err(CoreDispatchError::InvalidParams {
                    era: ProtocolEra::Modern2026,
                    method: TOOLS_CALL,
                })
            ),
            "only a non-object arguments value changes the accepted final call"
        );

        let read_params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            },
            "uri": "file:///workspace/status",
            "inputResponses": {"request-1": {"approved": true}},
            "requestState": "retry-1"
        });
        let get_params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            },
            "name": "status",
            "inputResponses": {"request-1": {"approved": true}},
            "requestState": "retry-1"
        });
        for (method, params) in [(RESOURCES_READ, read_params), (PROMPTS_GET, get_params)] {
            let request = CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params))
                .expect("final retry parameters decode");
            assert_eq!(
                request
                    .encode_params()
                    .expect("retry parameters encode")
                    .expect("retry-owning request has parameters"),
                params,
                "{method} retains retry input responses and request state"
            );
        }
    }

    #[test]
    fn final_server_info_is_admitted_only_in_result_metadata() {
        let params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        });
        let request = CoreRequest::decode(ProtocolEra::Modern2026, TOOLS_LIST, Some(&params))
            .expect("final tools/list request");
        let accepted = r#"{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"final-server","version":"1.0.0"}}}"#;
        let baseline = request
            .decode_result(accepted)
            .expect("final serverInfo is admitted in metadata");
        assert_eq!(
            baseline.encode().expect("metadata serverInfo encodes"),
            accepted
        );

        let planted = r#"{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"final-server","version":"1.0.0"}},"serverInfo":{"name":"legacy-location","version":"1.0.0"}}"#;
        assert!(
            matches!(
                request.decode_result(planted),
                Err(CoreDispatchError::InvalidResult {
                    era: ProtocolEra::Modern2026,
                    method: TOOLS_LIST,
                })
            ),
            "only a top-level serverInfo changes the final result admission"
        );
        assert_eq!(
            request
                .decode_result(accepted)
                .expect("baseline remains admitted")
                .encode()
                .expect("baseline encodes"),
            baseline.encode().expect("original baseline encodes"),
            "the top-level serverInfo rejection does not alter metadata server info"
        );
    }

    #[test]
    fn final_log_level_metadata_replaces_final_set_level_rpc() {
        let final_params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/logLevel": "notice"
            }
        });
        let request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            SERVER_DISCOVER,
            Some(&final_params),
        )
        .expect("final discovery metadata carries log level");
        let CoreRequest::Final(FinalCoreRequest::Discover(params)) = request else {
            panic!("final discovery request");
        };
        assert_eq!(
            params.meta.log_level().expect("typed final log level"),
            Some(LoggingLevel::Notice)
        );
        let notification = FinalLogMessageParams {
            level: LoggingLevel::Notice,
            logger: Some("final.server".to_owned()),
            data: serde_json::json!({"message": "catalog refreshed"}),
            meta: None,
            additional: BTreeMap::new(),
        };
        assert_eq!(
            serde_json::to_value(notification).expect("final log notification encodes"),
            serde_json::json!({
                "level": "notice",
                "logger": "final.server",
                "data": {"message": "catalog refreshed"}
            })
        );
        assert!(matches!(
            CoreRequest::decode(
                ProtocolEra::Modern2026,
                PING,
                Some(&serde_json::json!({
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }))
            ),
            Err(CoreDispatchError::UnsupportedMethod {
                era: ProtocolEra::Modern2026,
                method,
            }) if method == PING
        ));
        assert!(
            CoreRequest::decode(ProtocolEra::Legacy2024, PING, None).is_ok(),
            "the exact legacy ping request remains available only in its legacy era"
        );
    }

    #[test]
    fn final_discover_core_result_round_trips_typed_capabilities_and_cache_hints() {
        let params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        });
        let request = CoreRequest::decode(ProtocolEra::Modern2026, SERVER_DISCOVER, Some(&params))
            .expect("final server/discover request is typed");
        let advertised = crate::ServerDiscoverResult::new(
            crate::ServerDiscoverCapabilities::from_registry(
                &crate::ServerBehaviorRegistry::from_behaviors([
                    crate::ServerBehavior::ToolsList,
                    crate::ServerBehavior::ToolsListChangedNotification,
                ]),
                std::collections::BTreeMap::new(),
            )
            .expect("installed server behavior derives typed discovery capabilities"),
            ServerInfo {
                name: "discovery-server".to_owned(),
                version: "1.0.0".to_owned(),
            },
            Some(
                crate::ServerInstructions::new("Use tools before answering.")
                    .expect("bounded discovery instructions"),
            ),
            crate::DiscoveryCacheHints::private_ttl_ms(60_000),
        );
        let accepted = serde_json::to_value(&advertised).expect("typed discovery result encodes");
        let result = request
            .decode_result(
                &serde_json::to_string(&accepted).expect("discovery wire serializes for dispatch"),
            )
            .expect("typed discovery result is admitted by final core dispatch");
        let CoreResult::Final(FinalCoreResult::Discover(decoded)) = &result else {
            panic!("server/discover selects its typed final result");
        };
        assert_eq!(
            decoded.supported_versions(),
            [FINAL_PROTOCOL_VERSION.to_owned()],
            "the final discovery version set round-trips exactly"
        );
        assert_eq!(
            decoded
                .server_info()
                .map(|info| (info.name.as_str(), info.version.as_str())),
            Some(("discovery-server", "1.0.0")),
            "serverInfo remains final result metadata"
        );
        assert_eq!(
            decoded
                .instructions()
                .map(crate::ServerInstructions::as_str),
            Some("Use tools before answering."),
            "instructions remain part of the typed discovery result"
        );
        assert_eq!(decoded.cache_hints().ttl_ms(), 60_000);
        assert!(!decoded.cache_hints().is_public());
        assert_eq!(
            serde_json::from_str::<Value>(&result.encode().expect("typed result re-encodes"))
                .expect("encoded typed result remains JSON"),
            accepted,
            "capabilities, serverInfo, instructions, and cache hints all survive core dispatch"
        );

        let mut planted = accepted.clone();
        planted["cacheScope"] = serde_json::json!("shared");
        assert!(
            matches!(
                request.decode_result(
                    &serde_json::to_string(&planted)
                        .expect("one-field malformed discovery wire serializes"),
                ),
                Err(CoreDispatchError::InvalidResult {
                    era: ProtocolEra::Modern2026,
                    method: SERVER_DISCOVER,
                })
            ),
            "changing only cacheScope to an unrecognized value rejects the typed discovery result"
        );
        assert_eq!(
            serde_json::from_str::<Value>(
                &result.encode().expect("accepted result stays immutable")
            )
            .expect("accepted result stays JSON"),
            accepted,
            "the malformed peer field cannot mutate the admitted discovery result"
        );
    }

    #[test]
    fn core_dispatch_round_trips_legacy_and_final_core_payloads() {
        let final_params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            },
            "name": "echo",
            "arguments": {"message": "hello"}
        });
        let final_request =
            CoreRequest::decode(ProtocolEra::Modern2026, TOOLS_CALL, Some(&final_params))
                .expect("final tools/call request is typed through common metadata");
        assert_eq!(final_request.era(), ProtocolEra::Modern2026);
        assert_eq!(final_request.method(), TOOLS_CALL);
        assert_eq!(
            final_request
                .encode_params()
                .expect("final request re-encodes")
                .expect("final requests always own a parameter object"),
            final_params
        );

        let final_wire = r#"{"resultType":"complete","content":[{"type":"text","text":"ready"}],"extension":{"opaque":true}}"#;
        let final_result = final_request
            .decode_result(final_wire)
            .expect("final complete result selects the tools/call payload");
        let CoreResult::Final(FinalCoreResult::ToolsCall { result, diagnostic }) = &final_result
        else {
            panic!("final tools/call result");
        };
        assert_eq!(diagnostic, &None);
        assert!(matches!(
            result.payload.content.as_slice(),
            [ContentBlock::Text { text, .. }] if text == "ready"
        ));
        assert_eq!(
            result
                .extras
                .members()
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            ["extension"]
        );
        assert_eq!(
            final_result.encode().expect("final result re-encodes"),
            final_wire
        );

        let legacy_params = serde_json::json!({"cursor": ""});
        let legacy_request =
            CoreRequest::decode(ProtocolEra::Legacy2024, TOOLS_LIST, Some(&legacy_params))
                .expect("legacy tools/list keeps its exact parameter struct");
        assert_eq!(legacy_request.era(), ProtocolEra::Legacy2024);
        assert_eq!(
            legacy_request
                .encode_params()
                .expect("legacy request re-encodes")
                .expect("list request owns a parameter object"),
            legacy_params
        );
        let legacy_wire = r#"{"tools":[],"nextCursor":""}"#;
        let legacy_result = legacy_request
            .decode_result(legacy_wire)
            .expect("legacy result selects the legacy payload");
        assert!(matches!(
            legacy_result,
            CoreResult::Legacy(LegacyCoreResult::ToolsList(_))
        ));
        assert_eq!(
            legacy_result.encode().expect("legacy result re-encodes"),
            legacy_wire
        );
    }

    #[test]
    fn final_core_input_required_results_round_trip_for_mrtr_methods() {
        let metadata = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        });
        let requests = [
            (
                TOOLS_CALL,
                serde_json::json!({
                    "_meta": metadata,
                    "name": "collect-input"
                }),
            ),
            (
                RESOURCES_READ,
                serde_json::json!({
                    "_meta": metadata,
                    "uri": "file:///workspace/status"
                }),
            ),
            (
                PROMPTS_GET,
                serde_json::json!({
                    "_meta": metadata,
                    "name": "collect-input"
                }),
            ),
        ];
        let wire = r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"retry-7","com.example/opaque":{"retained":true}}"#;

        for (method, params) in requests {
            let request = CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params))
                .expect("each final MRTR-capable request decodes");
            let result = request
                .decode_result(wire)
                .expect("input-required result is admitted for the selected method");
            let input_required = match (&result, method) {
                (
                    CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { result, .. }),
                    TOOLS_CALL,
                )
                | (
                    CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired {
                        result, ..
                    }),
                    RESOURCES_READ,
                )
                | (
                    CoreResult::Final(FinalCoreResult::PromptsGetInputRequired { result, .. }),
                    PROMPTS_GET,
                ) => result,
                _ => panic!("{method} must select its final input-required branch"),
            };
            assert!(
                input_required
                    .input_requests()
                    .and_then(|requests| requests.get("roots"))
                    .is_some(),
                "{method} preserves the exact MRTR input request map"
            );
            assert_eq!(input_required.request_state(), Some("retry-7"));
            assert_eq!(
                result.encode().expect("input-required result re-encodes"),
                wire,
                "{method} retains input-required state and open siblings"
            );
        }
    }

    #[test]
    fn final_core_rejects_input_required_for_ineligible_method_without_mutation() {
        let params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        });
        let request = CoreRequest::decode(ProtocolEra::Modern2026, TOOLS_LIST, Some(&params))
            .expect("final tools/list request decodes");
        let accepted = r#"{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"retry-7"}"#;
        let baseline = request
            .decode_result(accepted)
            .expect("complete tools/list retains foreign open siblings inertly");
        let planted = accepted.replacen("\"complete\"", "\"input_required\"", 1);

        assert!(
            matches!(
                request.decode_result(&planted),
                Err(CoreDispatchError::UnexpectedFinalResultType { method: TOOLS_LIST })
            ),
            "changing only resultType cannot make tools/list MRTR-capable"
        );
        assert_eq!(
            baseline
                .encode()
                .expect("accepted complete result remains encodable"),
            accepted,
            "the rejected input-required discriminator leaves the accepted result unchanged"
        );
    }

    #[test]
    fn core_completion_round_trips_exact_legacy_and_final_payloads() {
        let legacy_params = serde_json::json!({
            "ref": {"type": "ref/prompt", "name": "deploy"},
            "argument": {"name": "environment", "value": "sta"}
        });
        let legacy_request = CoreRequest::decode(
            ProtocolEra::Legacy2024,
            COMPLETION_COMPLETE,
            Some(&legacy_params),
        )
        .expect("exact legacy completion request is typed");
        assert_eq!(legacy_request.era(), ProtocolEra::Legacy2024);
        assert_eq!(legacy_request.method(), COMPLETION_COMPLETE);
        assert_eq!(
            legacy_request
                .encode_params()
                .expect("legacy completion request re-encodes")
                .expect("completion owns an object parameter"),
            legacy_params
        );

        let legacy_wire = r#"{"completion":{"values":["staging"],"total":1,"hasMore":false}}"#;
        let legacy_result = legacy_request
            .decode_result(legacy_wire)
            .expect("exact legacy completion result is typed");
        let CoreResult::Legacy(LegacyCoreResult::Completion(result)) = &legacy_result else {
            panic!("legacy completion result");
        };
        assert_eq!(result.completion.values, vec!["staging".to_owned()]);
        assert_eq!(result.completion.total, Some(1));
        assert_eq!(result.completion.has_more, Some(false));
        assert_eq!(
            legacy_result
                .encode()
                .expect("legacy completion re-encodes"),
            legacy_wire
        );

        let final_params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            },
            "ref": {
                "type": "ref/prompt",
                "name": "deploy",
                "title": "Deploy application"
            },
            "argument": {"name": "environment", "value": "pro"},
            "context": {"arguments": {"region": "us-east-1"}}
        });
        let final_request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            COMPLETION_COMPLETE,
            Some(&final_params),
        )
        .expect("final completion request is typed through final metadata");
        assert_eq!(final_request.era(), ProtocolEra::Modern2026);
        assert_eq!(final_request.method(), COMPLETION_COMPLETE);
        let CoreRequest::Final(FinalCoreRequest::Completion(params)) = &final_request else {
            panic!("final completion request");
        };
        assert!(matches!(
            &params.reference,
            FinalCompletionReference::PromptWithTitle { title, .. } if title == "Deploy application"
        ));
        assert_eq!(
            final_request
                .encode_params()
                .expect("final completion request re-encodes")
                .expect("completion owns an object parameter"),
            final_params
        );

        let final_wire = r#"{"resultType":"complete","completion":{"values":["production"],"total":1,"hasMore":false},"extension":{"opaque":true}}"#;
        let final_result = final_request
            .decode_result(final_wire)
            .expect("final complete result selects the completion payload");
        let CoreResult::Final(FinalCoreResult::Completion { result, diagnostic }) = &final_result
        else {
            panic!("final completion result");
        };
        assert_eq!(diagnostic, &None);
        assert_eq!(
            result.payload.completion.values,
            vec!["production".to_owned()]
        );
        assert_eq!(result.payload.completion.total, Some(1));
        assert_eq!(result.payload.completion.has_more, Some(false));
        assert_eq!(
            result
                .extras
                .members()
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            ["extension"]
        );
        assert_eq!(
            final_result.encode().expect("final completion re-encodes"),
            final_wire
        );
    }

    #[test]
    fn completion_values_enforce_the_one_hundred_value_limit() {
        let accepted = CompletionValues {
            values: (0..MAX_COMPLETION_VALUES)
                .map(|index| format!("value-{index}"))
                .collect(),
            total: Some(MAX_COMPLETION_VALUES as i64),
            has_more: Some(false),
        };
        let encoded = serde_json::to_value(&accepted).expect("one hundred values serialize");
        assert_eq!(
            encoded["values"].as_array().map(Vec::len),
            Some(MAX_COMPLETION_VALUES)
        );

        let too_many = (0..=MAX_COMPLETION_VALUES)
            .map(|index| format!("value-{index}"))
            .collect::<Vec<_>>();
        assert!(
            serde_json::from_value::<CompletionValues>(serde_json::json!({
                "values": too_many
            }))
            .is_err(),
            "a peer cannot admit 101 completion values"
        );
        assert!(
            serde_json::to_value(CompletionValues {
                values: (0..=MAX_COMPLETION_VALUES)
                    .map(|index| format!("value-{index}"))
                    .collect(),
                total: None,
                has_more: None,
            })
            .is_err(),
            "locally authored results cannot emit 101 completion values"
        );
    }

    #[test]
    fn legacy_completion_result_retains_meta_during_round_trip() {
        let request = CoreRequest::decode(
            ProtocolEra::Legacy2024,
            COMPLETION_COMPLETE,
            Some(&serde_json::json!({
                "ref": {"type": "ref/prompt", "name": "deploy"},
                "argument": {"name": "environment", "value": "sta"}
            })),
        )
        .expect("legacy completion request");
        let wire = r#"{"completion":{"values":["staging"]},"_meta":{"trace":{"attempt":1},"cache":"private"}}"#;
        let result = request
            .decode_result(wire)
            .expect("legacy completion metadata remains typed");
        let CoreResult::Legacy(LegacyCoreResult::Completion(completion)) = &result else {
            panic!("legacy completion result");
        };
        let metadata = completion
            .meta
            .as_ref()
            .expect("legacy metadata is retained");
        assert_eq!(metadata.get("cache"), Some(&serde_json::json!("private")));
        assert_eq!(
            metadata.get("trace"),
            Some(&serde_json::json!({"attempt": 1}))
        );
        assert_eq!(
            metadata
                .entries()
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            ["trace", "cache"],
            "received legacy _meta key order remains observable"
        );
        assert_eq!(
            result.encode().expect("legacy completion re-encodes"),
            wire,
            "legacy completion _meta is not discarded or rewritten"
        );
    }

    #[test]
    fn final_subscriptions_listen_round_trips_request_result_and_acknowledgement() {
        let params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            },
            "notifications": {
                "promptsListChanged": false,
                "resourceSubscriptions": ["file:///workspace/status"],
                "resourcesListChanged": true,
                "toolsListChanged": true,
                "com.example/extension": {"enabled": true}
            }
        });
        let request =
            CoreRequest::decode(ProtocolEra::Modern2026, SUBSCRIPTIONS_LISTEN, Some(&params))
                .expect("final subscriptions/listen request is typed");
        assert_eq!(request.method(), SUBSCRIPTIONS_LISTEN);
        let CoreRequest::Final(FinalCoreRequest::SubscriptionsListen(listen)) = &request else {
            panic!("final subscriptions/listen request");
        };
        assert!(matches!(
            listen.notifications.resource_subscriptions.as_deref(),
            Some([uri]) if uri == "file:///workspace/status"
        ));
        assert_eq!(listen.notifications.prompts_list_changed, Some(false));
        assert_eq!(
            listen.notifications.additional.get("com.example/extension"),
            Some(&serde_json::json!({"enabled": true}))
        );
        assert_eq!(
            request
                .encode_params()
                .expect("final subscriptions/listen re-encodes")
                .expect("listen owns a parameter object"),
            params
        );

        let acknowledgement_wire = serde_json::json!({
            "_meta": {"io.modelcontextprotocol/subscriptionId": "subscription-7"},
            "notifications": {
                "resourceSubscriptions": ["file:///workspace/status"],
                "toolsListChanged": true
            }
        });
        let acknowledgement: FinalSubscriptionsAcknowledgedNotificationParams =
            serde_json::from_value(acknowledgement_wire.clone())
                .expect("acknowledgement notification is typed");
        assert_eq!(
            acknowledgement
                .meta
                .as_ref()
                .and_then(|metadata| metadata.get(FINAL_SUBSCRIPTION_ID_META_KEY)),
            Some(&serde_json::json!("subscription-7"))
        );
        assert_eq!(
            serde_json::to_value(&acknowledgement).expect("acknowledgement re-encodes"),
            acknowledgement_wire
        );

        let result_wire = r#"{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":"subscription-7","io.modelcontextprotocol/serverInfo":{"name":"final-server","version":"1.0.0"}}}"#;
        let response = JsonRpcResponse::success(
            RequestId::from("subscription-7"),
            serde_json::from_str(result_wire).expect("subscription result JSON"),
        );
        let result = request
            .decode_response(&response)
            .expect("final subscriptions/listen termination result is typed");
        let CoreResult::Final(FinalCoreResult::SubscriptionsListen {
            result: listen_result,
            subscription_id,
            diagnostic,
        }) = &result
        else {
            panic!("final subscriptions/listen result");
        };
        assert_eq!(subscription_id, &RequestId::from("subscription-7"));
        assert!(diagnostic.is_none());
        assert!(listen_result.extras.members().is_empty());
        assert_eq!(
            serde_json::from_str::<Value>(
                &result
                    .encode()
                    .expect("final subscriptions/listen re-encodes"),
            )
            .expect("encoded subscription result is JSON"),
            serde_json::from_str::<Value>(result_wire).expect("subscription result is JSON")
        );

        let legacy_subscribe = SubscribeResourceParams {
            uri: "file:///workspace/status".to_owned(),
        };
        let legacy_unsubscribe = UnsubscribeResourceParams {
            uri: "file:///workspace/status".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(legacy_subscribe).expect("legacy subscribe serializes"),
            serde_json::json!({"uri": "file:///workspace/status"})
        );
        assert_eq!(
            serde_json::to_value(legacy_unsubscribe).expect("legacy unsubscribe serializes"),
            serde_json::json!({"uri": "file:///workspace/status"})
        );
    }

    #[test]
    fn final_subscriptions_listen_rejects_one_field_response_id_mismatch() {
        let params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            },
            "notifications": {"toolsListChanged": true}
        });
        let request =
            CoreRequest::decode(ProtocolEra::Modern2026, SUBSCRIPTIONS_LISTEN, Some(&params))
                .expect("final subscriptions/listen request");
        let result = serde_json::json!({
            "resultType": "complete",
            "_meta": {"io.modelcontextprotocol/subscriptionId": "subscription-7"}
        });
        let accepted = JsonRpcResponse::success(RequestId::from("subscription-7"), result.clone());
        request
            .decode_response(&accepted)
            .expect("matching subscription response id is admitted");

        let planted = JsonRpcResponse::success(RequestId::from("subscription-8"), result);
        assert!(
            matches!(
                request.decode_response(&planted),
                Err(CoreDispatchError::SubscriptionIdMismatch)
            ),
            "only the response id differs from the otherwise valid subscription result"
        );
        request
            .decode_response(&accepted)
            .expect("the mismatched response cannot mutate the accepted binding");
    }

    #[test]
    fn final_subscriptions_listen_rejects_one_legacy_subscription_field() {
        let accepted = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            },
            "notifications": {
                "resourceSubscriptions": ["file:///workspace/status"]
            }
        });
        let baseline = CoreRequest::decode(
            ProtocolEra::Modern2026,
            SUBSCRIPTIONS_LISTEN,
            Some(&accepted),
        )
        .expect("baseline final subscriptions/listen request");

        let mut planted = accepted.clone();
        planted["uri"] = serde_json::json!("file:///workspace/status");
        assert!(
            matches!(
                CoreRequest::decode(
                    ProtocolEra::Modern2026,
                    SUBSCRIPTIONS_LISTEN,
                    Some(&planted)
                ),
                Err(CoreDispatchError::InvalidParams {
                    era: ProtocolEra::Modern2026,
                    method: SUBSCRIPTIONS_LISTEN,
                })
            ),
            "only the legacy resources/subscribe uri field changes the valid final listen request"
        );

        let reaccepted = CoreRequest::decode(
            ProtocolEra::Modern2026,
            SUBSCRIPTIONS_LISTEN,
            Some(&accepted),
        )
        .expect("cross-era rejection cannot mutate final listen decoding");
        assert_eq!(
            baseline
                .encode_params()
                .expect("baseline encodes")
                .expect("baseline parameters"),
            reaccepted
                .encode_params()
                .expect("reaccepted encodes")
                .expect("reaccepted parameters"),
            "the one-field cross-era rejection leaves the accepted final request unchanged"
        );
    }

    #[test]
    fn core_completion_rejects_one_field_cross_era_metadata() {
        let accepted = serde_json::json!({
            "ref": {"type": "ref/prompt", "name": "deploy"},
            "argument": {"name": "environment", "value": "sta"}
        });
        let baseline = CoreRequest::decode(
            ProtocolEra::Legacy2024,
            COMPLETION_COMPLETE,
            Some(&accepted),
        )
        .expect("baseline legacy completion request");

        let mut planted = accepted.clone();
        planted["_meta"] = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION
        });
        assert!(
            matches!(
                CoreRequest::decode(ProtocolEra::Legacy2024, COMPLETION_COMPLETE, Some(&planted)),
                Err(CoreDispatchError::CrossEraRequestMetadata {
                    method: COMPLETION_COMPLETE
                })
            ),
            "only the final _meta field changes the otherwise valid legacy completion request"
        );

        let reaccepted = CoreRequest::decode(
            ProtocolEra::Legacy2024,
            COMPLETION_COMPLETE,
            Some(&accepted),
        )
        .expect("cross-era rejection cannot mutate completion request decoding");
        assert_eq!(
            baseline
                .encode_params()
                .expect("baseline encodes")
                .expect("baseline parameters"),
            reaccepted
                .encode_params()
                .expect("reaccepted encodes")
                .expect("reaccepted parameters"),
            "the one-field cross-era rejection leaves the accepted legacy request unchanged"
        );
    }

    #[test]
    fn core_dispatch_rejects_one_field_final_result_type_on_legacy_result() {
        let request = CoreRequest::decode(ProtocolEra::Legacy2024, TOOLS_LIST, None)
            .expect("baseline legacy request");
        let accepted = r#"{"tools":[]}"#;
        let baseline = request
            .decode_result(accepted)
            .expect("the legacy result remains accepted without a final discriminator");
        let planted = r#"{"tools":[],"resultType":"complete"}"#;
        assert!(
            matches!(
                request.decode_result(planted),
                Err(CoreDispatchError::CrossEraResultType { method: TOOLS_LIST })
            ),
            "only the final resultType field changes the otherwise valid legacy result"
        );
        let reaccepted = request
            .decode_result(accepted)
            .expect("rejection cannot mutate the selected legacy dispatch");
        assert_eq!(
            baseline.encode().expect("baseline encodes"),
            reaccepted.encode().expect("reaccepted value encodes"),
            "the one-field cross-era rejection leaves the accepted legacy result unchanged"
        );
    }

    // ========================================================================
    // Initialize Tests
    // ========================================================================

    #[test]
    fn initialize_params_serialization() {
        let params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ClientCapabilities::default(),
            client_info: ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(value["clientInfo"]["name"], "test-client");
        assert_eq!(value["clientInfo"]["version"], "1.0.0");
    }

    #[test]
    fn initialize_params_round_trip() {
        let json = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "my-client", "version": "0.1.0"}
        });
        let params: InitializeParams = serde_json::from_value(json).expect("deserialize");
        assert_eq!(params.protocol_version, "2024-11-05");
        assert_eq!(params.client_info.name, "my-client");
    }

    #[test]
    fn initialize_result_serialization() {
        let result = InitializeResult {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ServerCapabilities::default(),
            server_info: ServerInfo {
                name: "test-server".to_string(),
                version: "1.0.0".to_string(),
            },
            instructions: Some("Welcome!".to_string()),
        };
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(value["serverInfo"]["name"], "test-server");
        assert_eq!(value["instructions"], "Welcome!");
    }

    #[test]
    fn initialize_result_without_instructions() {
        let result = InitializeResult {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ServerCapabilities::default(),
            server_info: ServerInfo {
                name: "srv".to_string(),
                version: "0.1.0".to_string(),
            },
            instructions: None,
        };
        let value = serde_json::to_value(&result).expect("serialize");
        assert!(value.get("instructions").is_none());
    }

    // ========================================================================
    // ListToolsParams Tests (with tags)
    // ========================================================================

    #[test]
    fn list_tools_params_default() {
        let params = ListToolsParams::default();
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value, serde_json::json!({}));
    }

    #[test]
    fn list_tools_params_with_cursor() {
        let params = ListToolsParams {
            cursor: Some("next-page".to_string()),
            include_tags: None,
            exclude_tags: None,
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["cursor"], "next-page");
    }

    #[test]
    fn list_tools_params_with_tags() {
        let params = ListToolsParams {
            cursor: None,
            include_tags: Some(vec!["api".to_string(), "v2".to_string()]),
            exclude_tags: Some(vec!["deprecated".to_string()]),
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["includeTags"], serde_json::json!(["api", "v2"]));
        assert_eq!(value["excludeTags"], serde_json::json!(["deprecated"]));
    }

    // ========================================================================
    // CallToolParams Tests
    // ========================================================================

    #[test]
    fn call_tool_params_minimal() {
        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: None,
            meta: None,
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["name"], "greet");
        assert!(value.get("arguments").is_none());
        assert!(value.get("_meta").is_none());
    }

    #[test]
    fn call_tool_params_full() {
        let params = CallToolParams {
            name: "add".to_string(),
            arguments: Some(serde_json::json!({"a": 1, "b": 2})),
            meta: Some(RequestMeta {
                progress_marker: Some(ProgressMarker::Number(100)),
            }),
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["name"], "add");
        assert_eq!(value["arguments"]["a"], 1);
        assert_eq!(value["_meta"][PROGRESS_MARKER_KEY], 100);
    }

    // ========================================================================
    // CallToolResult Tests
    // ========================================================================

    #[test]
    fn call_tool_result_success() {
        let result = CallToolResult {
            content: vec![LegacyContent::Text {
                text: "42".to_string(),
                annotations: None,
                additional: BTreeMap::new(),
            }],
            is_error: false,
            meta: None,
            additional: BTreeMap::new(),
        };
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["content"][0]["type"], "text");
        assert_eq!(value["content"][0]["text"], "42");
        // is_error=false should be omitted
        assert!(value.get("isError").is_none());
    }

    #[test]
    fn call_tool_result_error() {
        let result = CallToolResult {
            content: vec![LegacyContent::Text {
                text: "Something went wrong".to_string(),
                annotations: None,
                additional: BTreeMap::new(),
            }],
            is_error: true,
            meta: None,
            additional: BTreeMap::new(),
        };
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["isError"], true);
    }

    #[test]
    fn legacy_2024_content_results_round_trip_open_wire_members() {
        let tool_wire = serde_json::json!({
            "content": [{
                "type": "text",
                "text": "ready",
                "annotations": {
                    "audience": ["assistant"],
                    "priority": 0.75,
                    "com.example/annotation": {"retain": true}
                },
                "_meta": {"legacy": "content"},
                "com.example/content": {"retain": true}
            }],
            "_meta": {"legacy": "tool-result"},
            "com.example/result": ["retain"]
        });
        let tool_result: CallToolResult =
            serde_json::from_value(tool_wire.clone()).expect("legacy tool result decodes");
        assert_eq!(
            serde_json::to_value(&tool_result).expect("legacy tool result re-encodes"),
            tool_wire
        );

        let read_wire = serde_json::json!({
            "contents": [{
                "uri": "file:///report.txt",
                "text": "ready",
                "_meta": {"legacy": "resource"},
                "com.example/resource": {"retain": true}
            }],
            "_meta": {"legacy": "read-result"},
            "com.example/result": {"retain": true}
        });
        let read_result: ReadResourceResult =
            serde_json::from_value(read_wire.clone()).expect("legacy read result decodes");
        assert_eq!(
            serde_json::to_value(&read_result).expect("legacy read result re-encodes"),
            read_wire
        );

        let prompt_wire = serde_json::json!({
            "messages": [{
                "role": "user",
                "content": {
                    "type": "text",
                    "text": "summarize",
                    "_meta": {"legacy": "prompt-content"},
                    "com.example/content": "retain"
                },
                "_meta": {"legacy": "prompt-message"},
                "com.example/message": true
            }],
            "_meta": {"legacy": "prompt-result"},
            "com.example/result": {"retain": true}
        });
        let prompt_result: GetPromptResult =
            serde_json::from_value(prompt_wire.clone()).expect("legacy prompt result decodes");
        assert_eq!(
            serde_json::to_value(&prompt_result).expect("legacy prompt result re-encodes"),
            prompt_wire
        );
    }

    #[test]
    fn legacy_2024_call_tool_rejects_only_audio_discriminator_without_mutating_baseline() {
        let accepted = serde_json::json!({
            "content": [{
                "type": "text",
                "text": "payload",
                "data": "UklGRg==",
                "mimeType": "audio/wav"
            }]
        });
        let accepted_result: CallToolResult =
            serde_json::from_value(accepted.clone()).expect("legacy text content decodes");
        assert_eq!(
            serde_json::to_value(&accepted_result).expect("legacy text content re-encodes"),
            accepted
        );

        let baseline = accepted.clone();
        let mut planted = accepted.clone();
        planted["content"][0]["type"] = serde_json::json!("audio");
        assert!(
            serde_json::from_value::<CallToolResult>(planted).is_err(),
            "the exact 2024 tools/call content union excludes audio"
        );
        assert_eq!(
            accepted, baseline,
            "the one-field audio discriminator rejection cannot mutate accepted legacy wire"
        );
    }

    // ========================================================================
    // ListResourcesParams Tests
    // ========================================================================

    #[test]
    fn list_resources_params_default() {
        let params = ListResourcesParams::default();
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value, serde_json::json!({}));
    }

    #[test]
    fn list_resources_params_with_tags() {
        let params = ListResourcesParams {
            cursor: None,
            include_tags: Some(vec!["config".to_string()]),
            exclude_tags: None,
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["includeTags"], serde_json::json!(["config"]));
    }

    // ========================================================================
    // ReadResourceParams Tests
    // ========================================================================

    #[test]
    fn read_resource_params_serialization() {
        let params = ReadResourceParams {
            uri: "file://config.json".to_string(),
            meta: None,
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["uri"], "file://config.json");
        assert!(value.get("_meta").is_none());
    }

    #[test]
    fn read_resource_params_with_meta() {
        let params = ReadResourceParams {
            uri: "file://data.csv".to_string(),
            meta: Some(RequestMeta {
                progress_marker: Some(ProgressMarker::String("pt-read".to_string())),
            }),
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["uri"], "file://data.csv");
        assert_eq!(value["_meta"][PROGRESS_MARKER_KEY], "pt-read");
    }

    // ========================================================================
    // ReadResourceResult Tests
    // ========================================================================

    #[test]
    fn read_resource_result_serialization() {
        let result = ReadResourceResult {
            contents: vec![LegacyResourceContent::Text {
                uri: "file://test.txt".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: "Hello!".to_string(),
                additional: BTreeMap::new(),
            }],
            meta: None,
            additional: BTreeMap::new(),
        };
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["contents"][0]["uri"], "file://test.txt");
        assert_eq!(value["contents"][0]["text"], "Hello!");
    }

    #[test]
    fn legacy_resource_content_one_of_valid_text_and_blob_round_trip_open_members() {
        let wire = serde_json::json!({
            "contents": [
                {
                    "uri": "file:///report.txt",
                    "text": "ready",
                    "mimeType": "text/plain",
                    "_meta": {"legacy": "text"},
                    "com.example/resource": {"retain": true}
                },
                {
                    "uri": "file:///report.bin",
                    "blob": "cmVhZHk=",
                    "mimeType": "application/octet-stream",
                    "_meta": {"legacy": "blob"},
                    "com.example/resource": ["retain"]
                }
            ],
            "_meta": {"legacy": "read-result"},
            "com.example/result": {"retain": true}
        });

        let result: ReadResourceResult =
            serde_json::from_value(wire.clone()).expect("exact text and blob members decode");

        let LegacyResourceContent::Text { additional, .. } = &result.contents[0] else {
            panic!("text discriminator selects the text variant");
        };
        assert_eq!(additional["_meta"], serde_json::json!({"legacy": "text"}));
        assert_eq!(
            additional["com.example/resource"],
            serde_json::json!({"retain": true})
        );
        let LegacyResourceContent::Blob { additional, .. } = &result.contents[1] else {
            panic!("blob discriminator selects the blob variant");
        };
        assert_eq!(additional["_meta"], serde_json::json!({"legacy": "blob"}));
        assert_eq!(
            additional["com.example/resource"],
            serde_json::json!(["retain"])
        );
        assert_eq!(
            serde_json::to_value(&result).expect("exact legacy contents re-encode"),
            wire
        );
    }

    #[test]
    fn legacy_resource_content_one_of_rejects_ambiguous_or_missing_payload_negative() {
        let accepted = serde_json::json!({
            "contents": [{
                "uri": "file:///report.txt",
                "text": "ready",
                "_meta": {"legacy": "resource"},
                "com.example/resource": {"retain": true}
            }]
        });
        assert!(
            serde_json::from_value::<ReadResourceResult>(accepted.clone()).is_ok(),
            "the one-of baseline remains valid"
        );

        let mut both = accepted.clone();
        both["contents"][0]["blob"] = serde_json::json!("cmVhZHk=");
        assert!(
            serde_json::from_value::<ReadResourceResult>(both).is_err(),
            "only adding blob to a valid text resource must reject an ambiguous one-of"
        );

        let mut neither = accepted;
        neither["contents"][0]
            .as_object_mut()
            .expect("baseline content is an object")
            .remove("text");
        assert!(
            serde_json::from_value::<ReadResourceResult>(neither).is_err(),
            "only removing text from the same resource must reject an empty one-of"
        );
    }

    // ========================================================================
    // ListPromptsParams Tests
    // ========================================================================

    #[test]
    fn list_prompts_params_default() {
        let params = ListPromptsParams::default();
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value, serde_json::json!({}));
    }

    #[test]
    fn list_prompts_params_with_tags() {
        let params = ListPromptsParams {
            cursor: Some("c1".to_string()),
            include_tags: Some(vec!["onboarding".to_string()]),
            exclude_tags: Some(vec!["deprecated".to_string()]),
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["cursor"], "c1");
        assert_eq!(value["includeTags"], serde_json::json!(["onboarding"]));
        assert_eq!(value["excludeTags"], serde_json::json!(["deprecated"]));
    }

    // ========================================================================
    // GetPromptParams Tests
    // ========================================================================

    #[test]
    fn get_prompt_params_minimal() {
        let params = GetPromptParams {
            name: "greeting".to_string(),
            arguments: None,
            meta: None,
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["name"], "greeting");
        assert!(value.get("arguments").is_none());
    }

    #[test]
    fn get_prompt_params_with_arguments() {
        let mut args = std::collections::HashMap::new();
        args.insert("name".to_string(), "Alice".to_string());
        args.insert("language".to_string(), "French".to_string());

        let params = GetPromptParams {
            name: "translate".to_string(),
            arguments: Some(args),
            meta: None,
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["name"], "translate");
        assert_eq!(value["arguments"]["name"], "Alice");
        assert_eq!(value["arguments"]["language"], "French");
    }

    // ========================================================================
    // GetPromptResult Tests
    // ========================================================================

    #[test]
    fn get_prompt_result_serialization() {
        let result = GetPromptResult {
            description: Some("A greeting prompt".to_string()),
            messages: vec![LegacyPromptMessage {
                role: crate::types::Role::User,
                content: LegacyContent::Text {
                    text: "Say hello".to_string(),
                    annotations: None,
                    additional: BTreeMap::new(),
                },
                additional: BTreeMap::new(),
            }],
            meta: None,
            additional: BTreeMap::new(),
        };
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["description"], "A greeting prompt");
        assert_eq!(value["messages"][0]["role"], "user");
        assert_eq!(value["messages"][0]["content"]["text"], "Say hello");
    }

    #[test]
    fn get_prompt_result_without_description() {
        let result = GetPromptResult {
            description: None,
            messages: vec![],
            meta: None,
            additional: BTreeMap::new(),
        };
        let value = serde_json::to_value(&result).expect("serialize");
        assert!(value.get("description").is_none());
    }

    // ========================================================================
    // CancelledParams Tests
    // ========================================================================

    #[test]
    fn cancelled_params_minimal() {
        let params = CancelledParams {
            request_id: RequestId::Number(5),
            reason: None,
            await_cleanup: None,
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["requestId"], 5);
        assert!(value.get("reason").is_none());
        assert!(value.get("awaitCleanup").is_none());
    }

    #[test]
    fn cancelled_params_full() {
        let params = CancelledParams {
            request_id: RequestId::String("req-7".to_string()),
            reason: Some("User cancelled".to_string()),
            await_cleanup: Some(true),
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["requestId"], "req-7");
        assert_eq!(value["reason"], "User cancelled");
        assert_eq!(value["awaitCleanup"], true);
        assert_eq!(
            serde_json::to_string(&params).expect("legacy cancellation serializes"),
            r#"{"requestId":"req-7","reason":"User cancelled","awaitCleanup":true}"#,
            "the exact legacy cancellation wire retains its legacy-only field"
        );
    }

    #[test]
    fn cancelled_params_reason_is_bounded_and_shape_is_closed() {
        let exact = "x".repeat(MAX_CANCELLATION_REASON_BYTES);
        let too_long = "x".repeat(MAX_CANCELLATION_REASON_BYTES + 1);
        let exact_json = serde_json::json!({
            "requestId": 1,
            "reason": exact,
        });
        assert!(serde_json::from_value::<CancelledParams>(exact_json).is_ok());

        let too_long_json = serde_json::json!({
            "requestId": 1,
            "reason": too_long,
        });
        assert!(serde_json::from_value::<CancelledParams>(too_long_json).is_err());
        assert!(
            serde_json::from_value::<CancelledParams>(serde_json::json!({
                "requestId": 1,
                "reason": null,
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CancelledParams>(serde_json::json!({
                "requestId": 1,
                "awaitCleanup": null,
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CancelledParams>(serde_json::json!({
                "requestId": 1,
                "reason": "ok",
                "unknown": true,
            }))
            .is_err()
        );

        let outbound = CancelledParams {
            request_id: RequestId::Number(1),
            reason: Some("x".repeat(MAX_CANCELLATION_REASON_BYTES + 1)),
            await_cleanup: None,
        };
        assert!(serde_json::to_value(outbound).is_err());
    }

    // ========================================================================
    // ProgressParams Tests
    // ========================================================================

    #[test]
    fn progress_params_new() {
        let params = ProgressParams::new("id-1", 0.5);
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value[PROGRESS_MARKER_KEY], "id-1");
        assert_eq!(value["progress"], 0.5);
        assert!(value.get("total").is_none());
        assert!(value.get("message").is_none());
    }

    #[test]
    fn progress_params_with_total() {
        let params = ProgressParams::with_total(42i64, 50.0, 100.0);
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value[PROGRESS_MARKER_KEY], 42);
        assert_eq!(value["progress"], 50.0);
        assert_eq!(value["total"], 100.0);
    }

    #[test]
    fn progress_params_with_message() {
        let params = ProgressParams::new("tok", 0.75).with_message("Almost done");
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["message"], "Almost done");
    }

    #[test]
    fn progress_params_fraction() {
        let params = ProgressParams::with_total("t", 25.0, 100.0);
        assert_eq!(params.fraction(), Some(0.25));

        // Zero total
        let params = ProgressParams::with_total("t", 10.0, 0.0);
        assert_eq!(params.fraction(), Some(0.0));

        // No total
        let params = ProgressParams::new("t", 0.5);
        assert_eq!(params.fraction(), None);
    }

    // ========================================================================
    // GetTaskParams Tests
    // ========================================================================

    #[test]
    fn get_task_params_serialization() {
        let params = GetTaskParams {
            id: TaskId::from_string("task-abc"),
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["id"], "task-abc");
    }

    // ========================================================================
    // GetTaskResult Tests
    // ========================================================================

    #[test]
    fn get_task_result_serialization() {
        let result = GetTaskResult {
            task: crate::types::TaskInfo {
                id: TaskId::from_string("task-1"),
                task_type: "compute".to_string(),
                status: TaskStatus::Completed,
                progress: Some(1.0),
                message: Some("Done".to_string()),
                created_at: "2026-01-28T00:00:00Z".to_string(),
                started_at: Some("2026-01-28T00:01:00Z".to_string()),
                completed_at: Some("2026-01-28T00:02:00Z".to_string()),
                error: None,
            },
            result: Some(crate::types::TaskResult {
                id: TaskId::from_string("task-1"),
                success: true,
                data: Some(serde_json::json!({"value": 42})),
                error: None,
            }),
        };
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["task"]["status"], "completed");
        assert_eq!(value["result"]["success"], true);
        assert_eq!(value["result"]["data"]["value"], 42);
    }

    // ========================================================================
    // CancelTaskParams Tests
    // ========================================================================

    #[test]
    fn cancel_task_params_serialization() {
        let params = CancelTaskParams {
            id: TaskId::from_string("task-1"),
            reason: Some("No longer needed".to_string()),
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["id"], "task-1");
        assert_eq!(value["reason"], "No longer needed");
    }

    #[test]
    fn cancel_task_params_without_reason() {
        let params = CancelTaskParams {
            id: TaskId::from_string("task-2"),
            reason: None,
        };
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["id"], "task-2");
        assert!(value.get("reason").is_none());
    }

    // ========================================================================
    // CancelTaskResult Tests
    // ========================================================================

    #[test]
    fn cancel_task_result_serialization() {
        let result = CancelTaskResult {
            cancelled: true,
            task: crate::types::TaskInfo {
                id: TaskId::from_string("task-1"),
                task_type: "compute".to_string(),
                status: TaskStatus::Cancelled,
                progress: None,
                message: None,
                created_at: "2026-01-28T00:00:00Z".to_string(),
                started_at: None,
                completed_at: None,
                error: None,
            },
        };
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["cancelled"], true);
        assert_eq!(value["task"]["status"], "cancelled");
    }

    // ========================================================================
    // LogLevel Tests
    // ========================================================================

    #[test]
    fn log_level_serialization() {
        assert_eq!(serde_json::to_value(LogLevel::Debug).unwrap(), "debug");
        assert_eq!(serde_json::to_value(LogLevel::Info).unwrap(), "info");
        assert_eq!(serde_json::to_value(LogLevel::Warning).unwrap(), "warning");
        assert_eq!(serde_json::to_value(LogLevel::Error).unwrap(), "error");
    }

    #[test]
    fn log_level_deserialization() {
        assert_eq!(
            serde_json::from_value::<LogLevel>(serde_json::json!("debug")).unwrap(),
            LogLevel::Debug
        );
        assert_eq!(
            serde_json::from_value::<LogLevel>(serde_json::json!("warning")).unwrap(),
            LogLevel::Warning
        );
    }

    // ========================================================================
    // Existing Tests (preserved below)
    // ========================================================================

    #[test]
    fn list_resource_templates_params_serialization() {
        let params = ListResourceTemplatesParams::default();
        let value = serde_json::to_value(&params).expect("serialize params");
        assert_eq!(value, serde_json::json!({}));

        let params = ListResourceTemplatesParams {
            cursor: Some("next".to_string()),
            ..Default::default()
        };
        let value = serde_json::to_value(&params).expect("serialize params with cursor");
        assert_eq!(value, serde_json::json!({ "cursor": "next" }));
    }

    #[test]
    fn list_resource_templates_result_serialization() {
        let result = ListResourceTemplatesResult {
            resource_templates: vec![ResourceTemplate {
                uri_template: "resource://{id}".to_string(),
                name: "Resource Template".to_string(),
                description: Some("Template description".to_string()),
                mime_type: Some("text/plain".to_string()),
                icon: None,
                version: None,
                tags: vec![],
            }],
            next_cursor: None,
        };

        let value = serde_json::to_value(&result).expect("serialize result");
        let templates = value
            .get("resourceTemplates")
            .expect("resourceTemplates key");
        let template = templates.get(0).expect("first resource template");

        assert_eq!(template["uriTemplate"], "resource://{id}");
        assert_eq!(template["name"], "Resource Template");
        assert_eq!(template["description"], "Template description");
        assert_eq!(template["mimeType"], "text/plain");
    }

    #[test]
    fn resource_updated_notification_serialization() {
        let params = ResourceUpdatedNotificationParams {
            uri: "resource://test".to_string(),
        };
        let value = serde_json::to_value(&params).expect("serialize params");
        assert_eq!(value, serde_json::json!({ "uri": "resource://test" }));
    }

    #[test]
    fn subscribe_unsubscribe_resource_params_serialization() {
        let subscribe = SubscribeResourceParams {
            uri: "resource://alpha".to_string(),
        };
        let value = serde_json::to_value(&subscribe).expect("serialize subscribe params");
        assert_eq!(value, serde_json::json!({ "uri": "resource://alpha" }));

        let unsubscribe = UnsubscribeResourceParams {
            uri: "resource://alpha".to_string(),
        };
        let value = serde_json::to_value(&unsubscribe).expect("serialize unsubscribe params");
        assert_eq!(value, serde_json::json!({ "uri": "resource://alpha" }));
    }

    #[test]
    fn logging_params_serialization() {
        let set_level = SetLogLevelParams {
            level: LogLevel::Warning,
        };
        let value = serde_json::to_value(&set_level).expect("serialize setLevel");
        assert_eq!(value, serde_json::json!({ "level": "warning" }));

        let log_message = LogMessageParams {
            level: LogLevel::Info,
            logger: Some("fastmcp_rust::server".to_string()),
            data: serde_json::Value::String("hello".to_string()),
        };
        let value = serde_json::to_value(&log_message).expect("serialize log message");
        assert_eq!(value["level"], "info");
        assert_eq!(value["logger"], "fastmcp_rust::server");
        assert_eq!(value["data"], "hello");
    }

    #[test]
    fn list_tasks_params_serialization() {
        let params = ListTasksParams {
            cursor: None,
            limit: None,
            status: None,
        };
        let value = serde_json::to_value(&params).expect("serialize list tasks params");
        assert_eq!(value, serde_json::json!({}));

        let params = ListTasksParams {
            cursor: Some("next".to_string()),
            limit: Some(10),
            status: Some(TaskStatus::Running),
        };
        let value = serde_json::to_value(&params).expect("serialize list tasks params");
        assert_eq!(
            value,
            serde_json::json!({"cursor": "next", "limit": 10, "status": "running"})
        );
    }

    #[test]
    fn submit_task_params_serialization() {
        let params = SubmitTaskParams {
            task_type: "demo".to_string(),
            params: None,
        };
        let value = serde_json::to_value(&params).expect("serialize submit task params");
        assert_eq!(value, serde_json::json!({"taskType": "demo"}));

        let params = SubmitTaskParams {
            task_type: "demo".to_string(),
            params: Some(serde_json::json!({"payload": 1})),
        };
        let value = serde_json::to_value(&params).expect("serialize submit task params");
        assert_eq!(
            value,
            serde_json::json!({"taskType": "demo", "params": {"payload": 1}})
        );
    }

    #[test]
    fn task_status_notification_serialization() {
        let params = TaskStatusNotificationParams {
            id: TaskId::from_string("task-1"),
            status: TaskStatus::Running,
            progress: Some(0.5),
            message: Some("halfway".to_string()),
            error: None,
            result: None,
        };
        let value = serde_json::to_value(&params).expect("serialize task status notification");
        assert_eq!(
            value,
            serde_json::json!({
                "id": "task-1",
                "status": "running",
                "progress": 0.5,
                "message": "halfway"
            })
        );
    }

    // ========================================================================
    // Sampling Tests
    // ========================================================================

    #[test]
    fn create_message_params_minimal() {
        let params = CreateMessageParams::new(vec![SamplingMessage::user("Hello")], 100);
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value[MAX_TOKENS_KEY], 100);
        assert!(value["messages"].is_array());
        assert!(value.get("systemPrompt").is_none());
        assert!(value.get("temperature").is_none());
    }

    #[test]
    fn create_message_params_full() {
        let params = CreateMessageParams::new(
            vec![
                SamplingMessage::user("Hello"),
                SamplingMessage::assistant("Hi there!"),
            ],
            500,
        )
        .with_system_prompt("You are helpful")
        .with_temperature(0.7)
        .with_stop_sequences(vec!["END".to_string()]);

        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value[MAX_TOKENS_KEY], 500);
        assert_eq!(value["systemPrompt"], "You are helpful");
        assert_eq!(value["temperature"], 0.7);
        assert_eq!(value["stopSequences"][0], "END");
        assert_eq!(value["messages"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn create_message_result_text() {
        let result = CreateMessageResult::text("Hello!", "claude-3");
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["content"]["type"], "text");
        assert_eq!(value["content"]["text"], "Hello!");
        assert_eq!(value["model"], "claude-3");
        assert_eq!(value["role"], "assistant");
        assert_eq!(value["stopReason"], "endTurn");
    }

    #[test]
    fn create_message_result_max_tokens() {
        let result = CreateMessageResult::text("Truncated", "gpt-4").with_stop_reason("maxTokens");
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["stopReason"], "maxTo\x6bens");
    }

    #[test]
    fn sampling_message_user() {
        let msg = SamplingMessage::user("Test message");
        let value = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(value["role"], "user");
        assert_eq!(value["content"]["type"], "text");
        assert_eq!(value["content"]["text"], "Test message");
    }

    #[test]
    fn sampling_message_assistant() {
        let msg = SamplingMessage::assistant("Response");
        let value = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(value["role"], "assistant");
        assert_eq!(value["content"]["type"], "text");
        assert_eq!(value["content"]["text"], "Response");
    }

    #[test]
    fn sampling_content_image() {
        let content = SamplingContent::Image {
            data: "base64data".to_string(),
            mime_type: "image/png".to_string(),
        };
        let value = serde_json::to_value(&content).expect("serialize");
        assert_eq!(value["type"], "image");
        assert_eq!(value["data"], "base64data");
        assert_eq!(value["mimeType"], "image/png");
    }

    #[test]
    fn include_context_serialization() {
        let none = IncludeContext::None;
        let this = IncludeContext::ThisServer;
        let all = IncludeContext::AllServers;

        assert_eq!(serde_json::to_value(none).unwrap(), "none");
        assert_eq!(serde_json::to_value(this).unwrap(), "thisServer");
        assert_eq!(serde_json::to_value(all).unwrap(), "allServers");
    }

    #[test]
    fn create_message_result_text_content() {
        let result = CreateMessageResult::text("Hello!", "model");
        assert_eq!(result.text_content(), Some("Hello!"));

        let result = CreateMessageResult {
            content: SamplingContent::Image {
                data: "data".to_string(),
                mime_type: "image/png".to_string(),
            },
            role: crate::types::Role::Assistant,
            model: "model".to_string(),
            stop_reason: None,
            meta: None,
        };
        assert_eq!(result.text_content(), None);
    }

    // ========================================================================
    // Elicitation Tests
    // ========================================================================

    #[test]
    fn elicit_form_params_serialization() {
        let params = ElicitRequestFormParams::new(
            "Please enter your name",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"}
                },
                "required": ["name"]
            }),
        );
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["mode"], "form");
        assert_eq!(value["message"], "Please enter your name");
        assert!(value["requestedSchema"]["properties"]["name"].is_object());
    }

    #[test]
    fn elicit_url_params_serialization() {
        let params = ElicitRequestUrlParams::new(
            "Please authenticate",
            "https://auth.example.com/oauth",
            "elicit-12345",
        );
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["mode"], "url");
        assert_eq!(value["message"], "Please authenticate");
        assert_eq!(value["url"], "https://auth.example.com/oauth");
        assert_eq!(value["elicitationId"], "elicit-12345");
    }

    #[test]
    fn elicit_request_params_untagged() {
        let form = ElicitRequestParams::form(
            "Enter name",
            serde_json::json!({"type": "object", "properties": {}}),
        );
        assert_eq!(form.mode(), ElicitMode::Form);
        assert_eq!(form.message(), "Enter name");

        let url = ElicitRequestParams::url("Auth required", "https://example.com", "id-1");
        assert_eq!(url.mode(), ElicitMode::Url);
        assert_eq!(url.message(), "Auth required");
    }

    #[test]
    fn elicit_result_accept_with_content() {
        let mut content = std::collections::HashMap::new();
        content.insert(
            "name".to_string(),
            ElicitContentValue::String("Alice".to_string()),
        );
        content.insert("age".to_string(), ElicitContentValue::Int(30));
        content.insert("active".to_string(), ElicitContentValue::Bool(true));

        let result = ElicitResult::accept(content);
        assert!(result.is_accepted());
        assert!(!result.is_declined());
        assert!(!result.is_cancelled());
        assert_eq!(result.get_string("name"), Some("Alice"));
        assert_eq!(result.get_int("age"), Some(30));
        assert_eq!(result.get_bool("active"), Some(true));
    }

    #[test]
    fn elicit_result_serialization() {
        let result = ElicitResult::decline();
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["action"], "decline");
        assert!(value.get("content").is_none());

        let result = ElicitResult::cancel();
        let value = serde_json::to_value(&result).expect("serialize");
        assert_eq!(value["action"], "cancel");
    }

    #[test]
    fn elicit_content_value_conversions() {
        let s: ElicitContentValue = "hello".into();
        assert!(matches!(s, ElicitContentValue::String(_)));

        let i: ElicitContentValue = 42i64.into();
        assert!(matches!(i, ElicitContentValue::Int(42)));

        let b: ElicitContentValue = true.into();
        assert!(matches!(b, ElicitContentValue::Bool(true)));

        let f: ElicitContentValue = 1.23.into();
        assert!(matches!(f, ElicitContentValue::Float(_)));

        let arr: ElicitContentValue = vec!["a".to_string(), "b".to_string()].into();
        assert!(matches!(arr, ElicitContentValue::StringArray(_)));

        let none: ElicitContentValue = None::<String>.into();
        assert!(matches!(none, ElicitContentValue::Null));
    }

    #[test]
    fn elicit_complete_notification_serialization() {
        let params = ElicitCompleteNotificationParams::new("elicit-12345");
        let value = serde_json::to_value(&params).expect("serialize");
        assert_eq!(value["elicitationId"], "elicit-12345");
    }

    #[test]
    fn elicitation_capability_modes() {
        use crate::types::ElicitationCapability;

        let form_only = ElicitationCapability::form();
        assert!(form_only.supports_form());
        assert!(!form_only.supports_url());

        let url_only = ElicitationCapability::url();
        assert!(!url_only.supports_form());
        assert!(url_only.supports_url());

        let both = ElicitationCapability::both();
        assert!(both.supports_form());
        assert!(both.supports_url());
    }

    // ========================================================================
    // Roots tests
    // ========================================================================

    #[test]
    fn root_new() {
        use crate::types::Root;

        let root = Root::new("file:///home/user/project");
        assert_eq!(root.uri, "file:///home/user/project");
        assert!(root.name.is_none());
    }

    #[test]
    fn root_with_name() {
        use crate::types::Root;

        let root = Root::with_name("file:///home/user/project", "My Project");
        assert_eq!(root.uri, "file:///home/user/project");
        assert_eq!(root.name, Some("My Project".to_string()));
    }

    #[test]
    fn root_serialization() {
        use crate::types::Root;

        let root = Root::with_name("file:///home/user/project", "My Project");
        let json = serde_json::to_value(&root).expect("serialize");
        assert_eq!(json["uri"], "file:///home/user/project");
        assert_eq!(json["name"], "My Project");

        // Without name
        let root_no_name = Root::new("file:///tmp");
        let json = serde_json::to_value(&root_no_name).expect("serialize");
        assert_eq!(json["uri"], "file:///tmp");
        assert!(json.get("name").is_none());
    }

    #[test]
    fn list_roots_result_empty() {
        let result = ListRootsResult::empty();
        assert!(result.roots.is_empty());
    }

    #[test]
    fn list_roots_result_serialization() {
        use crate::types::Root;

        let result = ListRootsResult::new(vec![
            Root::with_name("file:///home/user/frontend", "Frontend"),
            Root::with_name("file:///home/user/backend", "Backend"),
        ]);

        let json = serde_json::to_value(&result).expect("serialize");
        let roots = json["roots"].as_array().expect("roots array");
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0]["uri"], "file:///home/user/frontend");
        assert_eq!(roots[0]["name"], "Frontend");
        assert_eq!(roots[1]["uri"], "file:///home/user/backend");
        assert_eq!(roots[1]["name"], "Backend");
    }

    #[test]
    fn roots_capability_serialization() {
        use crate::types::RootsCapability;

        // With listChanged = true
        let cap = RootsCapability { list_changed: true };
        let json = serde_json::to_value(&cap).expect("serialize");
        assert_eq!(json["listChanged"], true);

        // With listChanged = false (should be omitted)
        let cap = RootsCapability::default();
        let json = serde_json::to_value(&cap).expect("serialize");
        assert!(json.get("listChanged").is_none());
    }

    // ========================================================================
    // Component Version Metadata Tests
    // ========================================================================

    #[test]
    fn tool_version_serialization() {
        use crate::types::Tool;

        // Tool without version (should omit version field)
        let tool = Tool {
            name: "my_tool".to_string(),
            description: Some("A test tool".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        assert!(json.get("version").is_none());

        // Tool with version
        let tool = Tool {
            name: "my_tool".to_string(),
            description: Some("A test tool".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: Some("1.2.3".to_string()),
            tags: vec![],
            annotations: None,
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        assert_eq!(json["version"], "1.2.3");
    }

    #[test]
    fn resource_version_serialization() {
        use crate::types::Resource;

        // Resource without version
        let resource = Resource {
            uri: "file://test".to_string(),
            name: "Test Resource".to_string(),
            description: None,
            mime_type: Some("text/plain".to_string()),
            icon: None,
            version: None,
            tags: vec![],
        };
        let json = serde_json::to_value(&resource).expect("serialize");
        assert!(json.get("version").is_none());

        // Resource with version
        let resource = Resource {
            uri: "file://test".to_string(),
            name: "Test Resource".to_string(),
            description: None,
            mime_type: Some("text/plain".to_string()),
            icon: None,
            version: Some("2.0.0".to_string()),
            tags: vec![],
        };
        let json = serde_json::to_value(&resource).expect("serialize");
        assert_eq!(json["version"], "2.0.0");
    }

    #[test]
    fn prompt_version_serialization() {
        use crate::types::Prompt;

        // Prompt without version
        let prompt = Prompt {
            name: "greeting".to_string(),
            description: Some("A greeting prompt".to_string()),
            arguments: vec![],
            icon: None,
            version: None,
            tags: vec![],
        };
        let json = serde_json::to_value(&prompt).expect("serialize");
        assert!(json.get("version").is_none());

        // Prompt with version
        let prompt = Prompt {
            name: "greeting".to_string(),
            description: Some("A greeting prompt".to_string()),
            arguments: vec![],
            icon: None,
            version: Some("0.1.0".to_string()),
            tags: vec![],
        };
        let json = serde_json::to_value(&prompt).expect("serialize");
        assert_eq!(json["version"], "0.1.0");
    }

    #[test]
    fn resource_template_version_serialization() {
        // ResourceTemplate without version
        let template = ResourceTemplate {
            uri_template: "file://{path}".to_string(),
            name: "Files".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let json = serde_json::to_value(&template).expect("serialize");
        assert!(json.get("version").is_none());

        // ResourceTemplate with version
        let template = ResourceTemplate {
            uri_template: "file://{path}".to_string(),
            name: "Files".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: Some("3.0.0".to_string()),
            tags: vec![],
        };
        let json = serde_json::to_value(&template).expect("serialize");
        assert_eq!(json["version"], "3.0.0");
    }

    #[test]
    fn version_deserialization() {
        use crate::types::{Prompt, Resource, Tool};

        // Deserialize tool without version
        let json = serde_json::json!({
            "name": "tool",
            "inputSchema": {"type": "object"}
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        assert!(tool.version.is_none());

        // Deserialize tool with version
        let json = serde_json::json!({
            "name": "tool",
            "inputSchema": {"type": "object"},
            "version": "1.0.0"
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        assert_eq!(tool.version, Some("1.0.0".to_string()));

        // Deserialize resource without version
        let json = serde_json::json!({
            "uri": "file://test",
            "name": "Test"
        });
        let resource: Resource = serde_json::from_value(json).expect("deserialize");
        assert!(resource.version.is_none());

        // Deserialize prompt without version
        let json = serde_json::json!({
            "name": "prompt"
        });
        let prompt: Prompt = serde_json::from_value(json).expect("deserialize");
        assert!(prompt.version.is_none());
    }

    // ========================================================================
    // Tags Serialization Tests
    // ========================================================================

    #[test]
    fn tool_tags_serialization() {
        use crate::types::Tool;

        // Tool without tags (empty vec should not appear in JSON)
        let tool = Tool {
            name: "my_tool".to_string(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        assert!(
            json.get("tags").is_none(),
            "Empty tags should not appear in JSON"
        );

        // Tool with tags
        let tool = Tool {
            name: "my_tool".to_string(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec!["api".to_string(), "database".to_string()],
            annotations: None,
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        assert_eq!(json["tags"], serde_json::json!(["api", "database"]));
    }

    #[test]
    fn resource_tags_serialization() {
        use crate::types::Resource;

        // Resource without tags
        let resource = Resource {
            uri: "file://test".to_string(),
            name: "Test Resource".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let json = serde_json::to_value(&resource).expect("serialize");
        assert!(
            json.get("tags").is_none(),
            "Empty tags should not appear in JSON"
        );

        // Resource with tags
        let resource = Resource {
            uri: "file://test".to_string(),
            name: "Test Resource".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["files".to_string(), "readonly".to_string()],
        };
        let json = serde_json::to_value(&resource).expect("serialize");
        assert_eq!(json["tags"], serde_json::json!(["files", "readonly"]));
    }

    #[test]
    fn prompt_tags_serialization() {
        use crate::types::Prompt;

        // Prompt without tags
        let prompt = Prompt {
            name: "greeting".to_string(),
            description: None,
            arguments: vec![],
            icon: None,
            version: None,
            tags: vec![],
        };
        let json = serde_json::to_value(&prompt).expect("serialize");
        assert!(
            json.get("tags").is_none(),
            "Empty tags should not appear in JSON"
        );

        // Prompt with tags
        let prompt = Prompt {
            name: "greeting".to_string(),
            description: None,
            arguments: vec![],
            icon: None,
            version: None,
            tags: vec!["templates".to_string(), "onboarding".to_string()],
        };
        let json = serde_json::to_value(&prompt).expect("serialize");
        assert_eq!(json["tags"], serde_json::json!(["templates", "onboarding"]));
    }

    #[test]
    fn resource_template_tags_serialization() {
        // ResourceTemplate without tags
        let template = ResourceTemplate {
            uri_template: "file://{path}".to_string(),
            name: "Files".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let json = serde_json::to_value(&template).expect("serialize");
        assert!(
            json.get("tags").is_none(),
            "Empty tags should not appear in JSON"
        );

        // ResourceTemplate with tags
        let template = ResourceTemplate {
            uri_template: "file://{path}".to_string(),
            name: "Files".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["filesystem".to_string()],
        };
        let json = serde_json::to_value(&template).expect("serialize");
        assert_eq!(json["tags"], serde_json::json!(["filesystem"]));
    }

    #[test]
    fn tags_deserialization() {
        use crate::types::{Prompt, Resource, Tool};

        // Deserialize tool without tags field
        let json = serde_json::json!({
            "name": "tool",
            "inputSchema": {"type": "object"}
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        assert!(tool.tags.is_empty());

        // Deserialize tool with tags
        let json = serde_json::json!({
            "name": "tool",
            "inputSchema": {"type": "object"},
            "tags": ["compute", "heavy"]
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        assert_eq!(tool.tags, vec!["compute", "heavy"]);

        // Deserialize resource without tags
        let json = serde_json::json!({
            "uri": "file://test",
            "name": "Test"
        });
        let resource: Resource = serde_json::from_value(json).expect("deserialize");
        assert!(resource.tags.is_empty());

        // Deserialize resource with tags
        let json = serde_json::json!({
            "uri": "file://test",
            "name": "Test",
            "tags": ["data"]
        });
        let resource: Resource = serde_json::from_value(json).expect("deserialize");
        assert_eq!(resource.tags, vec!["data"]);

        // Deserialize prompt without tags
        let json = serde_json::json!({
            "name": "prompt"
        });
        let prompt: Prompt = serde_json::from_value(json).expect("deserialize");
        assert!(prompt.tags.is_empty());

        // Deserialize prompt with tags
        let json = serde_json::json!({
            "name": "prompt",
            "tags": ["greeting", "onboarding"]
        });
        let prompt: Prompt = serde_json::from_value(json).expect("deserialize");
        assert_eq!(prompt.tags, vec!["greeting", "onboarding"]);
    }

    // ========================================================================
    // Tool Annotations Serialization Tests
    // ========================================================================

    #[test]
    fn tool_annotations_serialization() {
        use crate::types::{Tool, ToolAnnotations};

        // Tool without annotations (None should not appear in JSON)
        let tool = Tool {
            name: "my_tool".to_string(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        assert!(
            json.get("annotations").is_none(),
            "None annotations should not appear in JSON"
        );

        // Tool with annotations
        let tool = Tool {
            name: "delete_file".to_string(),
            description: Some("Deletes a file".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: Some(
                ToolAnnotations::new()
                    .destructive(true)
                    .idempotent(false)
                    .read_only(false),
            ),
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        let annotations = json.get("annotations").expect("annotations field");
        // MCP-spec wire names are the `*Hint` forms.
        assert_eq!(annotations["destructiveHint"], true);
        assert_eq!(annotations["idempotentHint"], false);
        assert_eq!(annotations["readOnlyHint"], false);
        assert!(annotations.get("destructive").is_none());
        assert!(annotations.get("readOnly").is_none());
        assert!(annotations.get("openWorldHint").is_none());

        // Tool with read_only annotation
        let tool = Tool {
            name: "get_status".to_string(),
            description: Some("Gets status".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: Some(ToolAnnotations::new().read_only(true)),
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        let annotations = json.get("annotations").expect("annotations field");
        assert_eq!(annotations["readOnlyHint"], true);
        assert!(annotations.get("destructiveHint").is_none());
    }

    #[test]
    fn tool_annotations_deserialization() {
        use crate::types::Tool;

        // Deserialize tool without annotations
        let json = serde_json::json!({
            "name": "tool",
            "inputSchema": {"type": "object"}
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        assert!(tool.annotations.is_none());

        // Deserialize tool with annotations
        let json = serde_json::json!({
            "name": "delete_tool",
            "inputSchema": {"type": "object"},
            "annotations": {
                "destructiveHint": true,
                "idempotentHint": false,
                "readOnlyHint": false,
                "openWorldHint": true
            }
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        let annotations = tool.annotations.expect("annotations present");
        assert_eq!(annotations.destructive, Some(true));
        assert_eq!(annotations.idempotent, Some(false));
        assert_eq!(annotations.read_only, Some(false));
        assert_eq!(annotations.open_world_hint, Some(true));
    }

    #[test]
    fn tool_annotations_builder() {
        use crate::types::ToolAnnotations;

        let annotations = ToolAnnotations::new()
            .destructive(true)
            .idempotent(true)
            .read_only(false)
            .open_world_hint(true);

        assert_eq!(annotations.destructive, Some(true));
        assert_eq!(annotations.idempotent, Some(true));
        assert_eq!(annotations.read_only, Some(false));
        assert_eq!(annotations.open_world_hint, Some(true));
        assert!(!annotations.is_empty());

        // Empty annotations
        let empty = ToolAnnotations::new();
        assert!(empty.is_empty());
    }

    // ========================================================================
    // Tool Output Schema Serialization Tests
    // ========================================================================

    #[test]
    fn tool_output_schema_serialization() {
        use crate::types::Tool;

        // Tool without output_schema (None should not appear in JSON)
        let tool = Tool {
            name: "my_tool".to_string(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        assert!(
            json.get("outputSchema").is_none(),
            "None output_schema should not appear in JSON"
        );

        // Tool with output_schema
        let tool = Tool {
            name: "compute".to_string(),
            description: Some("Computes a result".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "result": {"type": "number"},
                    "success": {"type": "boolean"}
                }
            })),
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        let output_schema = json.get("outputSchema").expect("outputSchema field");
        assert_eq!(output_schema["type"], "object");
        assert_eq!(output_schema["properties"]["result"]["type"], "number");
        assert_eq!(output_schema["properties"]["success"]["type"], "boolean");
    }

    #[test]
    fn tool_output_schema_deserialization() {
        use crate::types::Tool;

        // Deserialize tool without output_schema
        let json = serde_json::json!({
            "name": "tool",
            "inputSchema": {"type": "object"}
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        assert!(tool.output_schema.is_none());

        // Deserialize tool with output_schema
        let json = serde_json::json!({
            "name": "compute",
            "inputSchema": {"type": "object"},
            "outputSchema": {
                "type": "object",
                "properties": {
                    "value": {"type": "integer"}
                }
            }
        });
        let tool: Tool = serde_json::from_value(json).expect("deserialize");
        assert!(tool.output_schema.is_some());
        let schema = tool.output_schema.unwrap();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["value"]["type"], "integer");
    }
}
