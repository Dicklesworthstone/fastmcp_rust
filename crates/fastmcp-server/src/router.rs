//! Request router for MCP servers.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::Poll;
use std::time::Duration;

use crate::FinalTaskRuntime;
use crate::Session;
use crate::bidirectional::{
    MrtrCompletedInputs, MrtrExchangeBinding, MrtrExchangeRegistry, MrtrInputRequest,
    MrtrInputRequests, MrtrInputRequired, MrtrRetry,
};
use crate::handler::{
    BidirectionalSenders, BoxFuture, FinalMethodOutcome, FinalToolOutcome,
    ProgressNotificationSender, UriParams, empty_final_result_meta, encode_final_complete_result,
};
use crate::handler::{
    BoxedCompletionHandler, BoxedPromptHandler, BoxedResourceHandler, BoxedToolHandler,
    CompletionHandler, PromptHandler, ResourceHandler, ToolErrorKind, ToolHandler,
};
#[cfg(test)]
use asupersync::time::wall_now;
use asupersync::types::Time;
use asupersync::{Budget, Cx, Outcome};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use fastmcp_core::logging::{debug, targets, trace};
use fastmcp_core::{
    McpContext, McpError, McpErrorCode, McpOutcome, McpResult, SessionState, block_on,
    sha256_bounded,
};
use fastmcp_protocol::common_types::{
    AbsoluteUri, Annotations, EmbeddedResourceContents, OpenMetadata, RawIcon,
};
use fastmcp_protocol::extensions::OFFICIAL_TASKS_EXTENSION_ID;
use fastmcp_protocol::methods::COMPLETION_COMPLETE;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::uri_template::ReversibleResourceTemplate;
use fastmcp_protocol::{
    AdmittedSchema, CacheScope, CallToolParams, CallToolResult, CompleteResult, Content,
    CoreRequest, CoreResult, FinalCallToolParams, FinalCallToolResult, FinalCompletionParams,
    FinalCompletionReference, FinalCompletionResult, FinalCoreRequest, FinalCoreResult,
    FinalGetPromptParams, FinalGetPromptResult, FinalListParams, FinalListPromptsResult,
    FinalListResourceTemplatesResult, FinalListResourcesResult, FinalListToolsResult, FinalPrompt,
    FinalPromptArgument, FinalReadResourceParams, FinalReadResourceResult, FinalResource,
    FinalResourceTemplate, FinalTool, FinalToolAnnotations, GetPromptParams, GetPromptResult,
    InitializeParams, InitializeResult, InputRequiredResult, JsonRpcRequest,
    LegacyCompletionParams, LegacyCompletionResult, LegacyContent, LegacyCoreRequest,
    LegacyPromptMessage, LegacyResourceContent, ListPromptsParams, ListPromptsResult,
    ListResourceTemplatesParams, ListResourceTemplatesResult, ListResourcesParams,
    ListResourcesResult, ListToolsParams, ListToolsResult, MissingRequiredClientCapabilityError,
    PROTOCOL_VERSION, ProgressMarker, Prompt, PromptMessage, ReadResourceParams,
    ReadResourceResult, Resource, ResourceContent, ResourceTemplate, ServerBehavior,
    ServerBehaviorRegistry, TemplateValue, Tool, admit_final_schema, exact_json_to_serde, validate,
    validate_strict,
};

/// Type alias for a notification sender callback.
///
/// This callback is used to send notifications (like progress updates) back to the client
/// during request handling. The callback receives a JSON-RPC request (notification format).
pub type NotificationSender = Arc<dyn Fn(JsonRpcRequest) + Send + Sync>;

/// Allowlisted transport provenance attached to a sanitized inbound request.
///
/// This deliberately contains no peer address, headers, cookies, or
/// credentials. Transport implementations retain those raw values inside their
/// authentication boundary and pass only one of these validated facts to the
/// server dispatch layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundRequestTransport {
    /// Standard input/output framing.
    Stdio,
    /// Streamable HTTP request handling.
    Http,
    /// Server-sent events transport.
    Sse,
    /// WebSocket transport.
    WebSocket,
    /// In-process transport used by embeddings and tests.
    Memory,
}

/// Sanitized, immutable ingress facts for one server dispatch.
///
/// The type intentionally has no `Clone`, `Serialize`, or `Debug`
/// implementation. In particular, it offers no channel for raw headers or
/// credentials: a transport must authenticate privately and construct this
/// context from its allowlisted provenance only. The server creates a fresh
/// request-scoped [`McpContext`] from these facts for every dispatch.
pub struct InboundRequestContext {
    cx: Cx,
    request_id: u64,
    transport: InboundRequestTransport,
}

impl InboundRequestContext {
    /// Creates sanitized facts after transport-owned authentication and request
    /// metadata validation have completed.
    #[must_use]
    pub fn new(cx: Cx, request_id: u64, transport: InboundRequestTransport) -> Self {
        Self {
            cx,
            request_id,
            transport,
        }
    }

    /// Returns the transport's allowlisted provenance fact.
    #[must_use]
    pub const fn transport(&self) -> InboundRequestTransport {
        self.transport
    }

    /// Returns the request identity selected by the transport.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub(crate) fn request_context(&self) -> McpContext {
        McpContext::new(self.cx.clone(), self.request_id)
    }
}

/// Tag filtering parameters for list operations.
#[derive(Debug, Clone, Default)]
pub struct TagFilters<'a> {
    /// Only include components with ALL of these tags (AND logic).
    pub include: Option<&'a [String]>,
    /// Exclude components with ANY of these tags (OR logic).
    pub exclude: Option<&'a [String]>,
}

impl<'a> TagFilters<'a> {
    /// Creates tag filters from include and exclude vectors.
    pub fn new(include: Option<&'a Vec<String>>, exclude: Option<&'a Vec<String>>) -> Self {
        Self {
            include: include.map(|v| v.as_slice()),
            exclude: exclude.map(|v| v.as_slice()),
        }
    }

    /// Returns true if the given component tags pass the filter.
    ///
    /// - Include filter: component must have ALL include tags (AND logic)
    /// - Exclude filter: component is rejected if it has ANY exclude tag (OR logic)
    /// - Tag matching is case-insensitive
    pub fn matches(&self, component_tags: &[String]) -> bool {
        // Normalize component tags to lowercase for comparison
        let component_tags_lower: Vec<String> =
            component_tags.iter().map(|t| t.to_lowercase()).collect();

        // Include filter: must have ALL specified tags
        if let Some(include) = self.include {
            // Empty include array means no filter (all pass)
            if !include.is_empty() {
                for tag in include {
                    let tag_lower = tag.to_lowercase();
                    if !component_tags_lower.contains(&tag_lower) {
                        return false;
                    }
                }
            }
        }

        // Exclude filter: rejected if has ANY specified tag
        if let Some(exclude) = self.exclude {
            for tag in exclude {
                let tag_lower = tag.to_lowercase();
                if component_tags_lower.contains(&tag_lower) {
                    return false;
                }
            }
        }

        true
    }
}

fn decode_cursor_offset(cursor: Option<&str>) -> McpResult<usize> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };

    let decoded = BASE64_STANDARD.decode(cursor).map_err(|_| {
        McpError::invalid_params("Invalid cursor (base64 decode failed)".to_string())
    })?;
    let v: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|_| McpError::invalid_params("Invalid cursor (JSON parse failed)".to_string()))?;
    let offset = v
        .get("offset")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| McpError::invalid_params("Invalid cursor (missing offset)".to_string()))?;

    usize::try_from(offset)
        .map_err(|_| McpError::invalid_params("Invalid cursor (offset too large)".to_string()))
}

fn parse_stateless_params<T: serde::de::DeserializeOwned>(
    params: Option<serde_json::Value>,
) -> McpResult<T> {
    let value = params.ok_or_else(|| McpError::invalid_params("Missing required parameters"))?;
    serde_json::from_value(value).map_err(|error| McpError::invalid_params(error.to_string()))
}

fn parse_stateless_params_or_default<T: serde::de::DeserializeOwned + Default>(
    params: Option<serde_json::Value>,
) -> McpResult<T> {
    match params {
        Some(value) => serde_json::from_value(value)
            .map_err(|error| McpError::invalid_params(error.to_string())),
        None => Ok(T::default()),
    }
}

/// Converts a completed stateless handler result through the final result
/// contract while preserving the original typed [`McpError`] on refusal.
fn encode_stateless_handler_result<T: serde::Serialize>(
    result: McpResult<T>,
) -> McpResult<serde_json::Value> {
    encode_final_complete_result(result?)
}

/// Encodes a handler-authored final tool result without reprojecting it through
/// the legacy result surface. This preserves the complete result's metadata
/// and inert open members under the protocol-owned final codec.
fn encode_final_tools_call_result(
    result: McpResult<CompleteResult<FinalCallToolResult>>,
) -> McpResult<serde_json::Value> {
    let result = result?;
    let encoded = CoreResult::Final(FinalCoreResult::ToolsCall {
        result,
        diagnostic: None,
    })
    .encode()
    .map_err(|error| McpError::internal_error(error.to_string()))?;
    serde_json::from_str(&encoded).map_err(McpError::from)
}

/// Encodes a framework-minted MRTR continuation without allowing a handler to
/// select or replay its opaque request state.
fn encode_mrtr_input_required_result(result: MrtrInputRequired) -> McpResult<serde_json::Value> {
    serde_json::to_value(result)
        .map_err(|_| McpError::internal_error("failed to encode MRTR input_required result"))
}

const MAX_MRTR_BINDING_BYTES: usize = 64 * 1024;
const MAX_MRTR_RAW_PARAMS_BYTES: usize = 256 * 1024;
const MAX_MRTR_RAW_INPUT_RESPONSES_BYTES: usize = 192 * 1024;
const MAX_MRTR_RAW_JSON_DEPTH: usize = 32;
const MAX_MRTR_RAW_JSON_VALUES: usize = 4_096;

struct MrtrRawJsonCounter {
    max_bytes: usize,
    bytes: usize,
}

impl Write for MrtrRawJsonCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.max_bytes.saturating_sub(self.bytes);
        if buffer.len() > remaining {
            return Err(io::Error::other("MRTR JSON byte limit exceeded"));
        }
        self.bytes += buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn admit_mrtr_raw_json_value(value: &serde_json::Value, max_bytes: usize) -> McpResult<()> {
    fn count_values(value: &serde_json::Value, depth: usize, values: &mut usize) -> McpResult<()> {
        if depth > MAX_MRTR_RAW_JSON_DEPTH {
            return Err(McpError::invalid_params(
                "MRTR JSON exceeds its nesting limit",
            ));
        }
        *values = values.saturating_add(1);
        if *values > MAX_MRTR_RAW_JSON_VALUES {
            return Err(McpError::invalid_params(
                "MRTR JSON exceeds its value limit",
            ));
        }
        match value {
            serde_json::Value::Array(items) => {
                for value in items {
                    count_values(value, depth + 1, values)?;
                }
            }
            serde_json::Value::Object(members) => {
                for value in members.values() {
                    count_values(value, depth + 1, values)?;
                }
            }
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => {}
        }
        Ok(())
    }

    let mut values = 0;
    count_values(value, 0, &mut values)?;
    let mut counter = MrtrRawJsonCounter {
        max_bytes,
        bytes: 0,
    };
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| McpError::invalid_params("MRTR JSON exceeds its byte limit"))
}

enum FinalMrtrDispatch {
    Fresh,
    Resume(MrtrCompletedInputs),
    InputRequired(serde_json::Value),
}

fn mrtr_digest(value: &impl serde::Serialize) -> McpResult<[u8; 32]> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| McpError::invalid_params("invalid MRTR operation binding"))?;
    let digest = sha256_bounded(&bytes, MAX_MRTR_BINDING_BYTES)
        .map_err(|_| McpError::invalid_params("MRTR operation binding exceeds its limit"))?;
    Ok(*digest.as_bytes())
}

fn final_mrtr_binding(
    request_ctx: &McpContext,
    method: &'static str,
    target: String,
    arguments: &impl serde::Serialize,
) -> McpResult<Option<MrtrExchangeBinding>> {
    if target.len() > MAX_MRTR_BINDING_BYTES {
        return Err(McpError::invalid_params("MRTR target exceeds its limit"));
    }
    // A binding is only consumable where retry state can live. Fresh
    // dispatches on a session-less context stay valid; the binding is
    // demanded again at the points that actually need it (retry resolution
    // and input_required issuance).
    let Some((session_partition, _revision)) = request_ctx.session_cache_partition() else {
        return Ok(None);
    };
    let principal_digest = request_ctx
        .auth()
        .map(|auth| {
            auth.session_owner()
                .map(|owner| Ok(*owner.as_bytes()))
                .unwrap_or_else(|| mrtr_digest(&auth))
        })
        .transpose()?;
    Ok(Some(MrtrExchangeBinding::new(
        method,
        target,
        mrtr_digest(arguments)?,
        session_partition,
        principal_digest,
    )))
}

fn handler_mrtr_input_requests(result: &InputRequiredResult) -> McpResult<MrtrInputRequests> {
    let input_requests = result
        .input_requests()
        .ok_or_else(|| McpError::invalid_params("MRTR input_required requires inputRequests"))?;
    if input_requests.members().is_empty() {
        return Err(McpError::invalid_params(
            "MRTR inputRequests must not be empty",
        ));
    }
    MrtrInputRequests::new(
        input_requests
            .members()
            .iter()
            .map(|member| {
                let value = exact_json_to_serde(&member.value)
                    .map_err(|_| McpError::invalid_params("invalid MRTR input request"))?;
                Ok((member.name.clone(), MrtrInputRequest::from_wire(&value)?))
            })
            .collect::<McpResult<Vec<_>>>()?,
    )
}

fn encode_final_task_result(
    result: fastmcp_protocol::tasks_extension::CreateTaskResult,
) -> McpResult<serde_json::Value> {
    let encoded = CoreResult::Final(FinalCoreResult::ToolsCallTask { result })
        .encode()
        .map_err(|error| McpError::internal_error(error.to_string()))?;
    serde_json::from_str(&encoded).map_err(McpError::from)
}

fn require_final_tasks_capability(metadata: &OpenMetadata) -> McpResult<()> {
    let declared = metadata
        .client_capabilities()
        .map_err(|_| McpError::invalid_params("invalid final client capabilities"))?
        .and_then(|capabilities| capabilities.get("extensions"))
        .and_then(serde_json::Value::as_object)
        .and_then(|extensions| extensions.get(OFFICIAL_TASKS_EXTENSION_ID))
        .and_then(serde_json::Value::as_object)
        .is_some_and(serde_json::Map::is_empty);
    if declared {
        return Ok(());
    }

    let mut extensions = serde_json::Map::new();
    extensions.insert(
        OFFICIAL_TASKS_EXTENSION_ID.to_owned(),
        serde_json::json!({}),
    );
    let missing = MissingRequiredClientCapabilityError::new(serde_json::json!({
        "extensions": serde_json::Value::Object(extensions)
    }))
    .map_err(|_| McpError::internal_error("failed to encode required Tasks capability"))?;
    Err(McpError::with_data(
        McpErrorCode::Custom(missing.jsonrpc_error_code()),
        "Required client capability is missing",
        missing.canonical_error_data(),
    ))
}

/// Admits the schemas a local tool declares for a final-dialect call.
///
/// The returned values own immutable copies of the declarations so one exact
/// admitted pair is used for both the pre-handler input check and the
/// post-handler output check. Legacy dispatch intentionally retains its raw
/// compatibility validators.
#[derive(Clone)]
struct FinalToolSchemas {
    input: AdmittedSchema,
    output: Option<AdmittedSchema>,
    errors: Option<FinalToolErrorStructuredContent>,
}

#[derive(Clone)]
struct FinalToolErrorStructuredContent {
    input_validation: serde_json::Value,
    handler: serde_json::Value,
}

const MAX_FINAL_TOOL_ERROR_STRUCTURED_CONTENT_BYTES: usize = 16 * 1024;

fn admit_final_tool_error_structured_content<H: ToolHandler + ?Sized>(
    handler: &H,
    output: &AdmittedSchema,
    kind: ToolErrorKind,
) -> McpResult<serde_json::Value> {
    let mapped = crate::catch_extension_unwind(|| {
        handler.final_tool_error_structured_content(kind)
    })
    .map_err(|_payload| {
        McpError::internal_error("tool error structured-content mapper panicked during admission")
    })?
    .ok_or_else(|| {
        McpError::internal_error(
            "tool declares outputSchema without a complete tool-error structured-content mapper",
        )
    })?;
    let encoded = serde_json::to_vec(&mapped).map_err(|_error| {
        McpError::internal_error("tool error structured-content mapper returned invalid JSON")
    })?;
    if encoded.len() > MAX_FINAL_TOOL_ERROR_STRUCTURED_CONTENT_BYTES {
        return Err(McpError::internal_error(
            "tool error structured-content mapper exceeded the registration limit",
        ));
    }
    if output.validate(&mapped).is_err() {
        return Err(McpError::internal_error(
            "tool error structured-content mapper does not satisfy outputSchema",
        ));
    }
    Ok(mapped)
}

fn admit_final_tool_schemas<H: ToolHandler + ?Sized>(
    input_schema: &serde_json::Value,
    output_schema: Option<&serde_json::Value>,
    handler: &H,
) -> McpResult<FinalToolSchemas> {
    if !input_schema.is_object() {
        return Err(McpError::internal_error(
            "tool declares a final input schema that is not an object",
        ));
    }
    if input_schema.get("type").and_then(serde_json::Value::as_str) != Some("object") {
        return Err(McpError::internal_error(
            "tool declares a final input schema without type object",
        ));
    }
    let input = admit_final_schema(input_schema.clone()).map_err(|_error| {
        McpError::internal_error("tool declares an invalid final input schema")
    })?;
    let output = output_schema
        .cloned()
        .map(|schema| {
            if !schema.is_object() {
                return Err(McpError::internal_error(
                    "tool declares a final output schema that is not an object",
                ));
            }
            admit_final_schema(schema).map_err(|_error| {
                McpError::internal_error("tool declares an invalid final output schema")
            })
        })
        .transpose()?;
    let errors = output
        .as_ref()
        .map(|output| -> McpResult<FinalToolErrorStructuredContent> {
            Ok(FinalToolErrorStructuredContent {
                input_validation: admit_final_tool_error_structured_content(
                    handler,
                    output,
                    ToolErrorKind::InputValidation,
                )?,
                handler: admit_final_tool_error_structured_content(
                    handler,
                    output,
                    ToolErrorKind::Handler,
                )?,
            })
        })
        .transpose()?;
    Ok(FinalToolSchemas {
        input,
        output,
        errors,
    })
}

/// One immutable catalog snapshot committed together with its dispatch target.
/// No list or validation path re-invokes the handler's definition hooks.
struct AdmittedToolRegistration {
    handler: BoxedToolHandler,
    definition: Tool,
    final_registration: Option<AdmittedFinalToolRegistration>,
    legacy_enabled: bool,
}

struct AdmittedFinalToolRegistration {
    final_definition: FinalTool,
    schemas: FinalToolSchemas,
    declares_final_tasks: bool,
}

/// Immutable final resource catalog data, including the legacy tag snapshot
/// used only for server-side list filtering.
struct AdmittedFinalResourceRegistration {
    definition: FinalResource,
    tags: Vec<String>,
}

/// Immutable final prompt catalog data, including the legacy tag snapshot
/// used only for server-side list filtering.
struct AdmittedFinalPromptRegistration {
    definition: FinalPrompt,
    tags: Vec<String>,
}

impl AdmittedToolRegistration {
    fn admit<H: ToolHandler + 'static>(
        handler: H,
        definition: Tool,
        legacy_enabled: bool,
    ) -> McpResult<Self> {
        let (exact_final_definition, declares_final_tasks) = crate::catch_extension_unwind(|| {
            (handler.final_definition(), handler.declares_final_tasks())
        })
        .map_err(|_payload| {
            McpError::internal_error("tool metadata hook panicked during admission")
        })?;
        let final_definition = match exact_final_definition {
            Some(definition) => definition,
            None => {
                let (title, icons, metadata) = crate::catch_extension_unwind(|| {
                    (
                        handler.final_title().map(str::to_owned),
                        handler.final_icons().map(|icons| icons.to_vec()),
                        handler.final_metadata().cloned(),
                    )
                })
                .map_err(|_payload| {
                    McpError::internal_error("tool metadata hook panicked during admission")
                })?;
                FinalTool {
                    name: definition.name.clone(),
                    title,
                    description: definition.description.clone(),
                    input_schema: definition.input_schema.clone(),
                    output_schema: definition.output_schema.clone(),
                    annotations: definition
                        .annotations
                        .clone()
                        .map(project_final_tool_annotations),
                    icons,
                    meta: metadata,
                }
            }
        };
        if final_definition.name != definition.name {
            return Err(McpError::internal_error(
                "tool's exact final definition name differs from its legacy definition name",
            ));
        }
        let schemas = admit_final_tool_schemas(
            &final_definition.input_schema,
            final_definition.output_schema.as_ref(),
            &handler,
        )?;
        Ok(Self {
            handler: Box::new(handler),
            definition,
            final_registration: Some(AdmittedFinalToolRegistration {
                final_definition,
                schemas,
                declares_final_tasks,
            }),
            legacy_enabled,
        })
    }

    fn legacy_only<H: ToolHandler + 'static>(handler: H, definition: Tool) -> Self {
        Self {
            handler: Box::new(handler),
            definition,
            final_registration: None,
            legacy_enabled: true,
        }
    }

    fn with_mounted_name(self, mounted_name: String) -> Self {
        use crate::handler::MountedToolHandler;

        let Self {
            handler,
            mut definition,
            mut final_registration,
            legacy_enabled,
        } = self;
        definition.name.clone_from(&mounted_name);
        if let Some(final_registration) = final_registration.as_mut() {
            final_registration
                .final_definition
                .name
                .clone_from(&mounted_name);
        }
        Self {
            handler: Box::new(MountedToolHandler::new(handler, mounted_name)),
            definition,
            final_registration,
            legacy_enabled,
        }
    }
}

/// Encodes a handler-authored final resource result without reprojecting it
/// through the legacy resource result surface. This preserves final embedded
/// resource fields, cache policy, metadata, and open members selected by the
/// handler.
fn encode_final_resources_read_result(
    result: McpResult<CompleteResult<FinalReadResourceResult>>,
) -> McpResult<serde_json::Value> {
    let result = result?;
    let encoded = CoreResult::Final(FinalCoreResult::ResourcesRead {
        result,
        diagnostic: None,
    })
    .encode()
    .map_err(|error| McpError::internal_error(error.to_string()))?;
    serde_json::from_str(&encoded).map_err(McpError::from)
}

/// Encodes a handler-authored final prompt result without reprojecting it
/// through the legacy prompt surface. This preserves final common content and
/// result metadata selected by the handler.
fn encode_final_prompts_get_result(
    result: McpResult<CompleteResult<FinalGetPromptResult>>,
) -> McpResult<serde_json::Value> {
    let result = result?;
    let encoded = CoreResult::Final(FinalCoreResult::PromptsGet {
        result,
        diagnostic: None,
    })
    .encode()
    .map_err(|error| McpError::internal_error(error.to_string()))?;
    serde_json::from_str(&encoded).map_err(McpError::from)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FinalCacheHintPolicy {
    list_ttl_ms: u64,
    resource_read_ttl_ms: u64,
    scope: CacheScope,
}

impl Default for FinalCacheHintPolicy {
    fn default() -> Self {
        Self {
            list_ttl_ms: 5 * 60 * 1_000,
            resource_read_ttl_ms: 60 * 60 * 1_000,
            scope: CacheScope::Private,
        }
    }
}

/// Encodes a server-authored final payload through the selected method's exact
/// `FinalCoreResult` composition. This preserves typed catalog and cache
/// fields instead of inserting unvalidated JSON after serialization.
fn encode_final_core_result<T>(
    result: McpResult<T>,
    select: impl FnOnce(CompleteResult<T>) -> FinalCoreResult,
) -> McpResult<serde_json::Value> {
    let result = CompleteResult::new(result?, empty_final_result_meta()?);
    let encoded = CoreResult::Final(select(result))
        .encode()
        .map_err(|error| McpError::internal_error(error.to_string()))?;
    serde_json::from_str(&encoded).map_err(McpError::from)
}

fn project_final_tool_annotations(
    annotations: fastmcp_protocol::ToolAnnotations,
) -> FinalToolAnnotations {
    FinalToolAnnotations {
        title: None,
        destructive: annotations.destructive,
        idempotent: annotations.idempotent,
        read_only: annotations.read_only,
        open_world_hint: annotations.open_world_hint,
    }
}

fn project_final_resource_catalog_entry(
    resource: Resource,
    title: Option<String>,
    icons: Option<Vec<RawIcon>>,
    annotations: Option<Annotations>,
    meta: Option<OpenMetadata>,
) -> McpResult<FinalResource> {
    let uri = AbsoluteUri::parse(resource.uri).map_err(|error| {
        McpError::internal_error(format!(
            "legacy resource URI cannot be projected into the final catalog: {error}",
        ))
    })?;
    Ok(FinalResource {
        uri,
        name: resource.name,
        title,
        description: resource.description,
        icons,
        mime_type: resource.mime_type,
        size: None,
        annotations,
        meta,
    })
}

/// Freezes one resource's modern catalog entry during registration.
///
/// Discovery must not call application hooks: a catalog observed by a final
/// peer has to remain the one that was admitted alongside its dispatch target.
fn admit_final_resource_definition<H: ResourceHandler + ?Sized>(
    handler: &H,
    resource: &Resource,
) -> McpResult<FinalResource> {
    if let Some(definition) =
        crate::catch_extension_unwind(|| handler.final_definition()).map_err(|_payload| {
            McpError::internal_error("resource final-definition hook panicked during admission")
        })?
    {
        if definition.uri.as_str() != resource.uri {
            return Err(McpError::internal_error(
                "resource exact final URI differs from its legacy definition URI",
            ));
        }
        return Ok(definition);
    }
    let (title, icons, annotations, meta) = crate::catch_extension_unwind(|| {
        (
            handler.final_title().map(str::to_owned),
            handler.final_icons().map(|icons| icons.to_vec()),
            handler.final_annotations().cloned(),
            handler.final_metadata().cloned(),
        )
    })
    .map_err(|_payload| {
        McpError::internal_error("resource metadata hook panicked during admission")
    })?;
    project_final_resource_catalog_entry(resource.clone(), title, icons, annotations, meta)
}

/// Freezes one resource template's final catalog entry during registration.
fn admit_final_resource_template_definition<H: ResourceHandler + ?Sized>(
    handler: Option<&H>,
    template: &ResourceTemplate,
) -> McpResult<FinalResourceTemplate> {
    if let Some(handler) = handler {
        if let Some(definition) =
            crate::catch_extension_unwind(|| handler.final_template_definition()).map_err(
                |_payload| {
                    McpError::internal_error(
                        "resource final-template-definition hook panicked during admission",
                    )
                },
            )?
        {
            if definition.uri_template != template.uri_template {
                return Err(McpError::internal_error(
                    "resource exact final template differs from its legacy template URI",
                ));
            }
            return Ok(definition);
        }
    }
    let (title, icons, annotations, meta) = match handler {
        Some(handler) => crate::catch_extension_unwind(|| {
            (
                handler.final_template_title().map(str::to_owned),
                handler.final_template_icons().map(|icons| icons.to_vec()),
                handler.final_template_annotations().cloned(),
                handler.final_template_metadata().cloned(),
            )
        })
        .map_err(|_payload| {
            McpError::internal_error("resource template metadata hook panicked during admission")
        })?,
        None => (None, None, None, None),
    };
    Ok(FinalResourceTemplate {
        uri_template: template.uri_template.clone(),
        name: template.name.clone(),
        title,
        description: template.description.clone(),
        icons,
        mime_type: template.mime_type.clone(),
        annotations,
        meta,
    })
}

/// Freezes one prompt's final catalog entry during registration.
fn admit_final_prompt_definition<H: PromptHandler + ?Sized>(
    handler: &H,
    prompt: &Prompt,
) -> McpResult<FinalPrompt> {
    if let Some(definition) =
        crate::catch_extension_unwind(|| handler.final_definition()).map_err(|_payload| {
            McpError::internal_error("prompt final-definition hook panicked during admission")
        })?
    {
        if definition.name != prompt.name {
            return Err(McpError::internal_error(
                "prompt exact final name differs from its legacy definition name",
            ));
        }
        return Ok(definition);
    }
    let (title, icons, meta) = crate::catch_extension_unwind(|| {
        (
            handler.final_title().map(str::to_owned),
            handler.final_icons().map(|icons| icons.to_vec()),
            handler.final_metadata().cloned(),
        )
    })
    .map_err(|_payload| {
        McpError::internal_error("prompt metadata hook panicked during admission")
    })?;
    let arguments = (!prompt.arguments.is_empty()).then(|| {
        prompt
            .arguments
            .iter()
            .map(|argument| FinalPromptArgument {
                name: argument.name.clone(),
                title: None,
                description: argument.description.clone(),
                required: Some(argument.required),
            })
            .collect()
    });
    Ok(FinalPrompt {
        name: prompt.name.clone(),
        title,
        description: prompt.description.clone(),
        icons,
        arguments,
        meta,
    })
}

/// Converts handler-owned content into the exact legacy result union.
///
/// Audio is valid only in the broader handler surface, never in the exact
/// 2024-11-05 content union. Refuse it rather than emitting an invalid legacy
/// response or silently changing the content type.
fn legacy_content_from_handler(content: Content) -> McpResult<LegacyContent> {
    match content {
        Content::Text { text } => Ok(LegacyContent::Text {
            text,
            annotations: None,
            additional: BTreeMap::new(),
        }),
        Content::Image { data, mime_type } => Ok(LegacyContent::Image {
            data,
            mime_type,
            annotations: None,
            additional: BTreeMap::new(),
        }),
        Content::Resource { resource } => Ok(LegacyContent::Resource {
            resource: legacy_resource_content_from_handler(resource)?,
            annotations: None,
            additional: BTreeMap::new(),
        }),
        Content::Audio { .. } => Err(McpError::internal_error(
            "legacy 2024 result content does not support audio",
        )),
    }
}

fn legacy_contents_from_handler(content: Vec<Content>) -> McpResult<Vec<LegacyContent>> {
    content
        .into_iter()
        .map(legacy_content_from_handler)
        .collect()
}

/// Converts handler-owned resource content into an exact legacy result item.
fn legacy_resource_content_from_handler(
    resource: ResourceContent,
) -> McpResult<LegacyResourceContent> {
    match (resource.text, resource.blob) {
        (Some(text), None) => Ok(LegacyResourceContent::Text {
            uri: resource.uri,
            text,
            mime_type: resource.mime_type,
            additional: BTreeMap::new(),
        }),
        (None, Some(blob)) => Ok(LegacyResourceContent::Blob {
            uri: resource.uri,
            blob,
            mime_type: resource.mime_type,
            additional: BTreeMap::new(),
        }),
        _ => Err(McpError::internal_error(
            "legacy 2024 resource content requires exactly one text or blob payload",
        )),
    }
}

fn legacy_resource_contents_from_handler(
    contents: Vec<ResourceContent>,
) -> McpResult<Vec<LegacyResourceContent>> {
    contents
        .into_iter()
        .map(legacy_resource_content_from_handler)
        .collect()
}

fn legacy_prompt_messages_from_handler(
    messages: Vec<PromptMessage>,
) -> McpResult<Vec<LegacyPromptMessage>> {
    messages
        .into_iter()
        .map(|PromptMessage { role, content }| {
            Ok(LegacyPromptMessage {
                role,
                content: legacy_content_from_handler(content)?,
                additional: BTreeMap::new(),
            })
        })
        .collect()
}

/// Promotes exact legacy resource content into a final resource result.
///
/// Legacy open members remain inert but are retained verbatim. In particular,
/// an untyped legacy `_meta` value stays in `additional` rather than acquiring
/// final-era metadata authority during the cross-era projection.
fn promote_legacy_resource_content(
    resource: LegacyResourceContent,
) -> McpResult<EmbeddedResourceContents> {
    let (uri, content, mime_type, additional) = match resource {
        LegacyResourceContent::Text {
            uri,
            text,
            mime_type,
            additional,
        } => (
            uri,
            LegacyEmbeddedContent::Text(text),
            mime_type,
            additional,
        ),
        LegacyResourceContent::Blob {
            uri,
            blob,
            mime_type,
            additional,
        } => (
            uri,
            LegacyEmbeddedContent::Blob(blob),
            mime_type,
            additional,
        ),
    };
    let uri = AbsoluteUri::parse(uri).map_err(|error| {
        McpError::internal_error(format!(
            "legacy resource content cannot be projected into the final result: {error}",
        ))
    })?;

    match content {
        LegacyEmbeddedContent::Text(text) => Ok(EmbeddedResourceContents::Text {
            uri,
            text,
            mime_type,
            meta: None,
            additional,
        }),
        LegacyEmbeddedContent::Blob(blob) => Ok(EmbeddedResourceContents::Blob {
            uri,
            blob,
            mime_type,
            meta: None,
            additional,
        }),
    }
}

enum LegacyEmbeddedContent {
    Text(String),
    Blob(String),
}

fn legacy_read_resource_params(params: FinalReadResourceParams) -> ReadResourceParams {
    ReadResourceParams {
        uri: params.uri.as_str().to_owned(),
        meta: None,
    }
}

fn encode_cursor_offset(offset: usize) -> String {
    let payload = serde_json::json!({ "offset": offset });
    let bytes = serde_json::to_vec(&payload).expect("cursor state must serialize");
    BASE64_STANDARD.encode(bytes)
}

/// Pages an already-filtered immutable final catalog.
///
/// Filtering must precede cursor arithmetic so an exact-legacy-only entry
/// cannot create an empty modern page or shift a final peer's cursor.
fn page_final_catalog<T: Clone>(
    items: Vec<T>,
    cursor: Option<&str>,
    page_size: Option<usize>,
) -> McpResult<(Vec<T>, Option<String>)> {
    let Some(page_size) = page_size else {
        return Ok((items, None));
    };
    let offset = decode_cursor_offset(cursor)?;
    let end = offset.saturating_add(page_size).min(items.len());
    Ok((
        items.get(offset..end).unwrap_or_default().to_vec(),
        (end < items.len()).then(|| encode_cursor_offset(end)),
    ))
}

const SANITIZED_HANDLER_PANIC_MESSAGE: &str = "Internal server error";
static NEXT_HANDLER_INCIDENT_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum number of peer-controlled label bytes admitted to the log-key hash.
///
/// Labels longer than this retain their exact byte length in logs, but their
/// correlation key covers only this bounded prefix. This keeps observability
/// useful without allowing an attacker to turn debug logging into unbounded
/// hashing work.
const LOG_LABEL_HASH_INPUT_LIMIT: usize = 4 * 1024;
const LOG_LABEL_DIGEST_PREFIX_BYTES: usize = 8;

#[derive(Clone, Copy)]
struct SafeLogLabel {
    byte_len: usize,
    hashed_bytes: usize,
    digest_prefix: [u8; LOG_LABEL_DIGEST_PREFIX_BYTES],
}

impl std::fmt::Display for SafeLogLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bytes={},sha256_prefix=", self.byte_len)?;
        for byte in self.digest_prefix {
            write!(f, "{byte:02x}")?;
        }
        if self.hashed_bytes < self.byte_len {
            write!(f, ",hashed_prefix_bytes={}", self.hashed_bytes)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for SafeLogLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

fn safe_log_label(value: &str) -> SafeLogLabel {
    let bytes = value.as_bytes();
    let hashed_bytes = bytes.len().min(LOG_LABEL_HASH_INPUT_LIMIT);
    let bounded_prefix = &bytes[..hashed_bytes];
    let mut digest_prefix = [0_u8; LOG_LABEL_DIGEST_PREFIX_BYTES];
    if let Ok(digest) = sha256_bounded(bounded_prefix, LOG_LABEL_HASH_INPUT_LIMIT) {
        digest_prefix.copy_from_slice(&digest.as_bytes()[..LOG_LABEL_DIGEST_PREFIX_BYTES]);
    }

    SafeLogLabel {
        byte_len: bytes.len(),
        hashed_bytes,
        digest_prefix,
    }
}

fn duplicate_registration_error(component: &'static str, key: &str) -> McpError {
    McpError::invalid_request(format!(
        "{component} already exists; component_key={}",
        safe_log_label(key)
    ))
}

fn compose_handler_budget(
    ambient: Budget,
    server_or_request: Budget,
    handler_timeout: Option<Duration>,
    now: Time,
) -> Budget {
    let inherited = ambient.meet(server_or_request);
    match handler_timeout {
        Some(timeout) if !timeout.is_zero() => inherited.tightened_by_timeout(now, timeout),
        Some(_) | None => inherited,
    }
}

fn budget_error(ctx: &McpContext) -> Option<McpError> {
    if ctx.ensure_live().is_err() {
        return Some(McpError::request_cancelled());
    }
    None
}

fn sanitized_handler_panic(_request_lifetime: &Cx, handler_class: &'static str) -> McpError {
    let incident_id = NEXT_HANDLER_INCIDENT_ID.fetch_add(1, Ordering::Relaxed);
    log::error!(
        target: "fastmcp_rust::handler",
        "handler terminated unexpectedly; incident_id={incident_id}; class={handler_class}; detail=panic_payload_redacted"
    );
    McpError::internal_error(SANITIZED_HANDLER_PANIC_MESSAGE)
}

fn sanitized_handler_internal_error(
    _request_lifetime: &Cx,
    handler_class: &'static str,
) -> McpError {
    let incident_id = NEXT_HANDLER_INCIDENT_ID.fetch_add(1, Ordering::Relaxed);
    log::error!(
        target: "fastmcp_rust::handler",
        "handler returned an opaque internal failure; incident_id={incident_id}; class={handler_class}; detail=internal_error_redacted"
    );
    McpError::internal_error(SANITIZED_HANDLER_PANIC_MESSAGE)
}

fn sanitize_handler_error(cx: &Cx, handler_class: &'static str, error: McpError) -> McpError {
    if error.code == McpErrorCode::InternalError {
        sanitized_handler_internal_error(cx, handler_class)
    } else {
        error
    }
}

const fn is_framework_terminal_tool_error(code: McpErrorCode) -> bool {
    matches!(
        code,
        McpErrorCode::InternalError | McpErrorCode::RequestCancelled
    )
}

fn read_handler_timeout(
    cx: &Cx,
    handler_class: &'static str,
    read: impl FnOnce() -> Option<Duration>,
) -> McpResult<Option<Duration>> {
    crate::catch_extension_unwind(read)
        .map_err(|_payload| sanitized_handler_panic(cx, handler_class))
}

fn run_handler<'a, T>(
    ctx: &McpContext,
    budget: Budget,
    handler_class: &'static str,
    make_future: impl FnOnce() -> BoxFuture<'a, McpOutcome<T>>,
) -> McpResult<McpOutcome<T>> {
    if let Some(error) = budget_error(ctx) {
        return Err(error);
    }

    let execution = crate::catch_extension_unwind(|| {
        let future = make_future();
        match budget.deadline {
            Some(deadline) => block_on(async move {
                asupersync::time::timeout_at(deadline, future)
                    .await
                    .map_err(|_elapsed| ())
            }),
            None => Ok(block_on(future)),
        }
    });

    match execution {
        Err(_payload) => Err(sanitized_handler_panic(ctx.cx(), handler_class)),
        Ok(Err(())) => Err(McpError::new(
            McpErrorCode::RequestCancelled,
            "Request timeout exceeded",
        )),
        Ok(Ok(outcome)) => {
            if let Some(error) = budget_error(ctx) {
                Err(error)
            } else {
                Ok(outcome)
            }
        }
    }
}

/// Drives one handler future without entering the legacy blocking dispatcher.
///
/// The future stays inside its request-owned child task: timeout drops the
/// pending future, and dropping the parent task's join cancels the child before
/// the parent can complete. This helper deliberately receives the child Cx
/// separately from the framework context so modern handlers can propagate that
/// structured capability to their own nested work.
async fn run_handler_in_request<'a, T>(
    ctx: &'a McpContext,
    request_cx: &'a Cx,
    budget: Budget,
    handler_class: &'static str,
    make_future: impl FnOnce(&'a Cx) -> BoxFuture<'a, McpOutcome<T>>,
) -> McpResult<McpOutcome<T>> {
    if request_cx.is_cancel_requested() || budget_error(ctx).is_some() {
        return Err(McpError::request_cancelled());
    }

    let future = crate::catch_extension_unwind(|| make_future(request_cx))
        .map_err(|_payload| sanitized_handler_panic(ctx.cx(), handler_class))?;
    let mut future = future;
    let poll_handler = std::future::poll_fn(|task_cx| {
        match crate::catch_extension_unwind(|| future.as_mut().poll(task_cx)) {
            Ok(Poll::Ready(outcome)) => Poll::Ready(Ok(outcome)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_payload) => Poll::Ready(Err(())),
        }
    });

    let outcome = match budget.deadline {
        Some(deadline) => match asupersync::time::timeout_at(deadline, poll_handler).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(())) => return Err(sanitized_handler_panic(ctx.cx(), handler_class)),
            Err(_elapsed) => {
                return Err(McpError::new(
                    McpErrorCode::RequestCancelled,
                    "Request timeout exceeded",
                ));
            }
        },
        None => match poll_handler.await {
            Ok(outcome) => outcome,
            Err(()) => return Err(sanitized_handler_panic(ctx.cx(), handler_class)),
        },
    };

    if request_cx.is_cancel_requested() || budget_error(ctx).is_some() {
        Err(McpError::request_cancelled())
    } else {
        Ok(outcome)
    }
}

fn derive_handler_context(
    request_ctx: &McpContext,
    progress_marker: Option<ProgressMarker>,
    notification_sender: Option<&NotificationSender>,
    bidirectional_senders: Option<&BidirectionalSenders>,
    protocol_era: ProtocolEra,
) -> McpContext {
    trace!(
        target: targets::HANDLER,
        "Deriving handler context for request {}",
        request_ctx.request_id()
    );
    let mut handler_ctx = request_ctx.clone();

    if let (Some(marker), Some(sender)) = (progress_marker, notification_sender) {
        let sender = sender.clone();
        let reporter = match protocol_era {
            ProtocolEra::Legacy2024 => ProgressNotificationSender::new(marker, move |request| {
                sender(request);
            })
            .into_reporter(),
            ProtocolEra::Modern2026 => {
                ProgressNotificationSender::new_final(marker, move |request| {
                    sender(request);
                })
                .into_reporter()
            }
        };
        handler_ctx = handler_ctx.with_progress_reporter(reporter);
    }

    if let Some(senders) = bidirectional_senders {
        if let Some(ref sampling) = senders.sampling {
            handler_ctx = handler_ctx.with_sampling(sampling.clone());
        }
        if let Some(ref elicitation) = senders.elicitation {
            handler_ctx = handler_ctx.with_elicitation(elicitation.clone());
        }
    }

    handler_ctx
}

fn final_progress_marker(metadata: &OpenMetadata) -> McpResult<Option<ProgressMarker>> {
    metadata
        .get("progressToken")
        .map(|value| {
            serde_json::from_value(value.clone()).map_err(|_| {
                McpError::invalid_params("final progressToken must be a string or integer")
            })
        })
        .transpose()
}

/// Routes MCP requests to the appropriate handlers.
pub struct Router {
    tools: HashMap<String, AdmittedToolRegistration>,
    tool_order: Vec<String>,
    completion_handler: Option<BoxedCompletionHandler>,
    /// Whether the installed completion handler was admitted for final dispatch.
    final_completion_enabled: bool,
    resources: HashMap<String, BoxedResourceHandler>,
    /// Static resources visible to exact MCP 2024-11-05 only.
    final_only_resources: HashSet<String>,
    /// Immutable final catalog entries. Absence means exact-legacy-only.
    final_resources: HashMap<String, AdmittedFinalResourceRegistration>,
    resource_order: Vec<String>,
    prompts: HashMap<String, BoxedPromptHandler>,
    /// Prompts visible to exact MCP 2024-11-05 only.
    final_only_prompts: HashSet<String>,
    /// Immutable final catalog entries. Absence means exact-legacy-only.
    final_prompts: HashMap<String, AdmittedFinalPromptRegistration>,
    prompt_order: Vec<String>,
    resource_templates: HashMap<String, ResourceTemplateEntry>,
    resource_template_order: Vec<String>,
    /// Pre-sorted template keys by specificity (most specific first).
    /// Updated whenever templates are added/modified.
    sorted_template_keys: Vec<String>,
    /// Whether to enforce strict input validation (reject extra properties).
    strict_input_validation: bool,
    /// Optional list page size for cursor-based pagination.
    ///
    /// When `None`, list methods return all items in a single response and
    /// `nextCursor` is always omitted.
    list_page_size: Option<usize>,
    /// Cache policy emitted on exact modern catalog and resource-read results.
    final_cache_hints: FinalCacheHintPolicy,
    /// Application-owned durable final Tasks runtime used only after the
    /// request metadata has admitted the official extension.
    final_task_runtime: Option<FinalTaskRuntime>,
    /// Bounded, process-local final request-state records for tool, resource,
    /// and prompt retries. A state is accepted only if this router issued it.
    mrtr_exchanges: Arc<MrtrExchangeRegistry>,
}

impl Router {
    /// Creates a new empty router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            tool_order: Vec::new(),
            completion_handler: None,
            final_completion_enabled: false,
            resources: HashMap::new(),
            final_only_resources: HashSet::new(),
            final_resources: HashMap::new(),
            resource_order: Vec::new(),
            prompts: HashMap::new(),
            final_only_prompts: HashSet::new(),
            final_prompts: HashMap::new(),
            prompt_order: Vec::new(),
            resource_templates: HashMap::new(),
            resource_template_order: Vec::new(),
            sorted_template_keys: Vec::new(),
            strict_input_validation: false,
            list_page_size: None,
            final_cache_hints: FinalCacheHintPolicy::default(),
            final_task_runtime: None,
            mrtr_exchanges: Arc::new(MrtrExchangeRegistry::new()),
        }
    }

    pub(crate) fn set_final_task_runtime(&mut self, runtime: Option<FinalTaskRuntime>) {
        self.final_task_runtime = runtime;
    }

    /// Sets the list pagination page size.
    ///
    /// When set, list methods (`tools/list`, `resources/list`,
    /// `resources/templates/list`, and `prompts/list`) will page results using
    /// opaque base64 cursors.
    pub fn set_list_page_size(&mut self, page_size: Option<usize>) {
        self.list_page_size = page_size.filter(|n| *n > 0);
    }

    /// Sets the cache hints emitted by final catalog and resource-read
    /// responses. The default is a five-minute private catalog TTL and a
    /// one-hour private resource-read TTL.
    pub fn set_final_cache_hint_policy(
        &mut self,
        list_ttl_ms: u64,
        resource_read_ttl_ms: u64,
        scope: CacheScope,
    ) {
        self.final_cache_hints = FinalCacheHintPolicy {
            list_ttl_ms,
            resource_read_ttl_ms,
            scope,
        };
    }

    /// Returns the active final cache-hint policy as
    /// `(list_ttl_ms, resource_read_ttl_ms, scope)`.
    #[must_use]
    pub const fn final_cache_hint_policy(&self) -> (u64, u64, CacheScope) {
        (
            self.final_cache_hints.list_ttl_ms,
            self.final_cache_hints.resource_read_ttl_ms,
            self.final_cache_hints.scope,
        )
    }

    /// Sets whether to use strict input validation.
    ///
    /// When enabled, tool input validation will reject any properties not
    /// explicitly defined in the tool's input schema (enforces `additionalProperties: false`).
    ///
    /// When disabled (default), extra properties are allowed unless the schema
    /// explicitly sets `additionalProperties: false`.
    pub fn set_strict_input_validation(&mut self, strict: bool) {
        self.strict_input_validation = strict;
    }

    /// Returns whether strict input validation is enabled.
    #[must_use]
    pub fn strict_input_validation(&self) -> bool {
        self.strict_input_validation
    }

    /// Rebuilds the sorted template keys vector.
    /// Called after any modification to resource_templates.
    fn rebuild_sorted_template_keys(&mut self) {
        self.sorted_template_keys = self.resource_templates.keys().cloned().collect();
        self.sorted_template_keys.sort_by(|a, b| {
            let entry_a = &self.resource_templates[a];
            let entry_b = &self.resource_templates[b];
            let (a_literals, a_literal_segments, a_segments) = entry_a.specificity;
            let (b_literals, b_literal_segments, b_segments) = entry_b.specificity;
            b_literals
                .cmp(&a_literals)
                .then(b_literal_segments.cmp(&a_literal_segments))
                .then(b_segments.cmp(&a_segments))
                .then_with(|| a.cmp(b))
        });
    }

    /// Adds a tool handler.
    ///
    /// If a tool with the same name already exists, it will be replaced.
    /// Use [`add_tool_with_behavior`](Self::add_tool_with_behavior) for
    /// finer control over duplicate handling.
    pub fn add_tool<H: ToolHandler + 'static>(&mut self, handler: H) -> McpResult<()> {
        self.add_tool_with_behavior(handler, crate::DuplicateBehavior::Replace)
    }

    /// Adds an intentionally exact-2024-only tool handler.
    ///
    /// This is the explicit escape hatch for a legacy definition that cannot
    /// satisfy final schema admission. The tool remains available to exact
    /// MCP 2024-11-05 list and call routes, but is absent from every modern
    /// catalog and modern dispatch lookup. Ordinary [`Self::add_tool`] never
    /// falls back to this path.
    pub fn add_legacy_tool<H: ToolHandler + 'static>(&mut self, handler: H) -> McpResult<()> {
        self.add_legacy_tool_with_behavior(handler, crate::DuplicateBehavior::Replace)
    }

    /// Adds a tool handler with specified duplicate behavior.
    ///
    /// Returns `Err` if duplicate policy rejects the name or if the candidate's
    /// immutable definition, schemas, final metadata, or required error mapper
    /// cannot be admitted. Every error is returned before catalog mutation.
    pub fn add_tool_with_behavior<H: ToolHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        self.add_tool_registration_with_behavior(handler, behavior, true, true)
    }

    /// Adds an exact-final-only tool with duplicate handling.
    pub(crate) fn add_final_tool_with_behavior<H: ToolHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        self.add_tool_registration_with_behavior(handler, behavior, true, false)
    }

    /// Adds an intentionally exact-2024-only tool with duplicate policy.
    ///
    /// The definition is snapshotted before mutation, but no final definition,
    /// schema, metadata, or error-mapper hook is read. This prevents an
    /// explicitly legacy-only registration from accidentally claiming modern
    /// support while retaining the same duplicate semantics as ordinary tools.
    pub fn add_legacy_tool_with_behavior<H: ToolHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        self.add_tool_registration_with_behavior(handler, behavior, false, true)
    }

    fn add_tool_registration_with_behavior<H: ToolHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
        admit_final: bool,
        legacy_enabled: bool,
    ) -> Result<(), McpError> {
        let def = crate::catch_extension_unwind(|| handler.definition()).map_err(|_payload| {
            McpError::internal_error("tool definition hook panicked during admission")
        })?;
        let name = &def.name;

        let existed = self.tools.contains_key(name);
        if existed {
            match behavior {
                crate::DuplicateBehavior::Error => {
                    return Err(duplicate_registration_error("Tool", name));
                }
                crate::DuplicateBehavior::Warn => {
                    log::warn!(
                        target: "fastmcp_rust::router",
                        "tool already exists, keeping original; tool_key={}",
                        safe_log_label(name)
                    );
                    return Ok(());
                }
                crate::DuplicateBehavior::Replace => {
                    log::debug!(
                        target: "fastmcp_rust::router",
                        "replacing tool; tool_key={}",
                        safe_log_label(name)
                    );
                    // Fall through to insert
                }
                crate::DuplicateBehavior::Ignore => {
                    return Ok(());
                }
            }
        }

        // Admission must finish before any map or ordering mutation. In
        // particular, a rejected replacement must retain the prior handler
        // and its admitted schemas for both protocol eras.
        let name = def.name.clone();
        let admitted = if admit_final {
            AdmittedToolRegistration::admit(handler, def, legacy_enabled)?
        } else {
            AdmittedToolRegistration::legacy_only(handler, def)
        };
        self.tools.insert(name.clone(), admitted);
        if !existed {
            self.tool_order.push(name);
        }
        Ok(())
    }

    /// Registers the handler for `completion/complete`.
    ///
    /// Completion has one server-wide dispatch target rather than a catalog
    /// entry. Re-registering replaces the prior target, matching the ordinary
    /// component registration semantics.
    pub fn add_completion_handler<H: CompletionHandler + 'static>(&mut self, handler: H) {
        self.completion_handler = Some(Box::new(handler));
        self.final_completion_enabled = true;
    }

    /// Registers a completion handler for exact MCP 2024-11-05 dispatch only.
    pub fn add_legacy_completion_handler<H: CompletionHandler + 'static>(&mut self, handler: H) {
        self.completion_handler = Some(Box::new(handler));
        self.final_completion_enabled = false;
    }

    /// Returns whether a `completion/complete` handler is installed.
    #[must_use]
    pub fn has_completion_handler(&self) -> bool {
        self.completion_handler.is_some()
    }

    /// Adds a resource handler.
    ///
    /// If a resource with the same URI already exists, it will be replaced.
    /// Use [`add_resource_with_behavior`](Self::add_resource_with_behavior) for
    /// finer control over duplicate handling.
    pub fn add_resource<H: ResourceHandler + 'static>(&mut self, handler: H) {
        if let Err(error) = self.add_resource_registration_with_behavior(
            handler,
            crate::DuplicateBehavior::Replace,
            true,
            true,
        ) {
            log::warn!(
                target: "fastmcp_rust::router",
                "rejected resource registration; code={:?}",
                error.code
            );
        }
    }

    /// Adds an intentionally exact-2024-only resource handler.
    pub fn add_legacy_resource<H: ResourceHandler + 'static>(&mut self, handler: H) {
        if let Err(error) = self.add_resource_registration_with_behavior(
            handler,
            crate::DuplicateBehavior::Replace,
            false,
            true,
        ) {
            log::warn!(
                target: "fastmcp_rust::router",
                "rejected exact-2024-only resource registration; code={:?}",
                error.code
            );
        }
    }

    /// Adds a resource handler with specified duplicate behavior.
    ///
    /// Returns `Err` if behavior is [`crate::DuplicateBehavior::Error`] and the
    /// resource URI already exists.
    pub fn add_resource_with_behavior<H: ResourceHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        self.add_resource_registration_with_behavior(handler, behavior, true, true)
    }

    /// Adds an exact-final-only resource or resource template with duplicate handling.
    pub(crate) fn add_final_resource_with_behavior<H: ResourceHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        self.add_resource_registration_with_behavior(handler, behavior, true, false)
    }

    /// Adds an exact-2024-only resource handler with duplicate handling.
    pub fn add_legacy_resource_with_behavior<H: ResourceHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        self.add_resource_registration_with_behavior(handler, behavior, false, true)
    }

    fn add_resource_registration_with_behavior<H: ResourceHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
        admit_final: bool,
        legacy_enabled: bool,
    ) -> Result<(), McpError> {
        let (template, def) =
            crate::catch_extension_unwind(|| (handler.template(), handler.definition())).map_err(
                |_payload| {
                    McpError::internal_error("resource definition hook panicked during admission")
                },
            )?;

        // Check for duplicates
        let key = match template.as_ref() {
            Some(template) => template.uri_template.clone(),
            None => def.uri.clone(),
        };

        let exists = if template.is_some() {
            self.resource_templates.contains_key(&key)
        } else {
            self.resources.contains_key(&key)
        };

        if exists {
            match behavior {
                crate::DuplicateBehavior::Error => {
                    return Err(duplicate_registration_error("Resource", &key));
                }
                crate::DuplicateBehavior::Warn => {
                    log::warn!(
                        target: "fastmcp_rust::router",
                        "resource already exists, keeping original; resource_key={}",
                        safe_log_label(&key)
                    );
                    return Ok(());
                }
                crate::DuplicateBehavior::Replace => {
                    log::debug!(
                        target: "fastmcp_rust::router",
                        "replacing resource; resource_key={}",
                        safe_log_label(&key)
                    );
                    // Fall through to insert
                }
                crate::DuplicateBehavior::Ignore => {
                    return Ok(());
                }
            }
        }

        if let Some(template) = template {
            let (matcher, specificity) = admit_resource_template(&template.uri_template)?;
            let final_definition = admit_final
                .then(|| admit_final_resource_template_definition(Some(&handler), &template))
                .transpose()?;
            let boxed: BoxedResourceHandler = Box::new(handler);
            let is_new = !self.resource_templates.contains_key(&template.uri_template);
            let entry = ResourceTemplateEntry {
                matcher,
                specificity,
                template: template.clone(),
                handler: Some(boxed),
                final_definition,
                legacy_enabled,
            };
            self.resource_templates
                .insert(template.uri_template.clone(), entry);
            if is_new {
                self.resource_template_order.push(template.uri_template);
            }
            self.rebuild_sorted_template_keys();
        } else {
            let final_definition = admit_final
                .then(|| admit_final_resource_definition(&handler, &def))
                .transpose()?;
            let boxed: BoxedResourceHandler = Box::new(handler);
            let is_new = !self.resources.contains_key(&def.uri);
            self.resources.insert(def.uri.clone(), boxed);
            if legacy_enabled {
                self.final_only_resources.remove(&def.uri);
            } else {
                self.final_only_resources.insert(def.uri.clone());
            }
            match final_definition {
                Some(final_definition) => {
                    self.final_resources.insert(
                        def.uri.clone(),
                        AdmittedFinalResourceRegistration {
                            definition: final_definition,
                            tags: def.tags.clone(),
                        },
                    );
                }
                None => {
                    self.final_resources.remove(&def.uri);
                }
            }
            if is_new {
                self.resource_order.push(def.uri);
            }
        }

        Ok(())
    }

    /// Adds a resource template definition.
    ///
    /// If a template with the same URI template already exists, its definition
    /// is replaced while any registered handler is retained. Use
    /// [`add_resource_template_with_behavior`](Self::add_resource_template_with_behavior)
    /// for finer control over duplicate handling.
    pub fn add_resource_template(&mut self, template: ResourceTemplate) {
        let key = template.uri_template.clone();
        if let Err(error) =
            self.add_resource_template_with_behavior(template, crate::DuplicateBehavior::Replace)
        {
            log::warn!(
                target: "fastmcp_rust::router",
                "rejected resource template definition; template_key={}; code={:?}",
                safe_log_label(&key),
                error.code
            );
        }
    }

    /// Adds an exact-2024-only resource template definition.
    pub fn add_legacy_resource_template(&mut self, template: ResourceTemplate) {
        let key = template.uri_template.clone();
        if let Err(error) = self.add_resource_template_registration_with_behavior(
            template,
            crate::DuplicateBehavior::Replace,
            false,
        ) {
            log::warn!(
                target: "fastmcp_rust::router",
                "rejected exact-2024-only resource template; template_key={}; code={:?}",
                safe_log_label(&key),
                error.code
            );
        }
    }

    /// Adds a resource template definition with specified duplicate behavior.
    ///
    /// Replacing a definition retains an existing handler registered for the
    /// same URI template. Returns `Err` when behavior is
    /// [`crate::DuplicateBehavior::Error`] and the URI template already exists.
    pub fn add_resource_template_with_behavior(
        &mut self,
        template: ResourceTemplate,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        self.add_resource_template_registration_with_behavior(template, behavior, true)
    }

    /// Adds an exact-2024-only resource template with duplicate handling.
    pub fn add_legacy_resource_template_with_behavior(
        &mut self,
        template: ResourceTemplate,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        self.add_resource_template_registration_with_behavior(template, behavior, false)
    }

    fn add_resource_template_registration_with_behavior(
        &mut self,
        template: ResourceTemplate,
        behavior: crate::DuplicateBehavior,
        admit_final: bool,
    ) -> Result<(), McpError> {
        let key = template.uri_template.clone();
        let existed = self.resource_templates.contains_key(&key);

        if existed {
            match behavior {
                crate::DuplicateBehavior::Error => {
                    return Err(duplicate_registration_error("Resource template", &key));
                }
                crate::DuplicateBehavior::Warn => {
                    log::warn!(
                        target: "fastmcp_rust::router",
                        "resource template already exists, keeping original; template_key={}",
                        safe_log_label(&key)
                    );
                    return Ok(());
                }
                crate::DuplicateBehavior::Replace => {
                    log::debug!(
                        target: "fastmcp_rust::router",
                        "replacing resource template definition; template_key={}",
                        safe_log_label(&key)
                    );
                }
                crate::DuplicateBehavior::Ignore => return Ok(()),
            }
        }

        let (matcher, specificity) = admit_resource_template(&key)?;
        let final_definition = admit_final
            .then(|| {
                admit_final_resource_template_definition::<dyn ResourceHandler>(None, &template)
            })
            .transpose()?;
        let needs_rebuild = match self.resource_templates.get_mut(&key) {
            Some(existing) => {
                existing.template = template;
                existing.matcher = matcher;
                existing.specificity = specificity;
                existing.final_definition = final_definition;
                existing.legacy_enabled = true;
                false // Key already exists, order unchanged
            }
            None => {
                self.resource_templates.insert(
                    key.clone(),
                    ResourceTemplateEntry {
                        matcher,
                        specificity,
                        template,
                        handler: None,
                        final_definition,
                        legacy_enabled: true,
                    },
                );
                true // New key added, need to rebuild
            }
        };
        if needs_rebuild {
            self.resource_template_order.push(key);
            self.rebuild_sorted_template_keys();
        }
        Ok(())
    }

    /// Adds a prompt handler.
    ///
    /// If a prompt with the same name already exists, it will be replaced.
    /// Use [`add_prompt_with_behavior`](Self::add_prompt_with_behavior) for
    /// finer control over duplicate handling.
    pub fn add_prompt<H: PromptHandler + 'static>(&mut self, handler: H) {
        if let Err(error) = self.add_prompt_registration_with_behavior(
            handler,
            crate::DuplicateBehavior::Replace,
            true,
            true,
        ) {
            log::warn!(
                target: "fastmcp_rust::router",
                "rejected prompt registration; code={:?}",
                error.code
            );
        }
    }

    /// Adds an intentionally exact-2024-only prompt handler.
    pub fn add_legacy_prompt<H: PromptHandler + 'static>(&mut self, handler: H) {
        if let Err(error) = self.add_prompt_registration_with_behavior(
            handler,
            crate::DuplicateBehavior::Replace,
            false,
            true,
        ) {
            log::warn!(
                target: "fastmcp_rust::router",
                "rejected exact-2024-only prompt registration; code={:?}",
                error.code
            );
        }
    }

    /// Adds a prompt handler with specified duplicate behavior.
    ///
    /// Returns `Err` if behavior is [`crate::DuplicateBehavior::Error`] and the
    /// prompt name already exists.
    pub fn add_prompt_with_behavior<H: PromptHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        self.add_prompt_registration_with_behavior(handler, behavior, true, true)
    }

    /// Adds an exact-final-only prompt with duplicate handling.
    pub(crate) fn add_final_prompt_with_behavior<H: PromptHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        self.add_prompt_registration_with_behavior(handler, behavior, true, false)
    }

    /// Adds an exact-2024-only prompt with duplicate handling.
    pub fn add_legacy_prompt_with_behavior<H: PromptHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
    ) -> Result<(), McpError> {
        self.add_prompt_registration_with_behavior(handler, behavior, false, true)
    }

    fn add_prompt_registration_with_behavior<H: PromptHandler + 'static>(
        &mut self,
        handler: H,
        behavior: crate::DuplicateBehavior,
        admit_final: bool,
        legacy_enabled: bool,
    ) -> Result<(), McpError> {
        let def = crate::catch_extension_unwind(|| handler.definition()).map_err(|_payload| {
            McpError::internal_error("prompt definition hook panicked during admission")
        })?;
        let name = &def.name;

        let existed = self.prompts.contains_key(name);
        if existed {
            match behavior {
                crate::DuplicateBehavior::Error => {
                    return Err(duplicate_registration_error("Prompt", name));
                }
                crate::DuplicateBehavior::Warn => {
                    log::warn!(
                        target: "fastmcp_rust::router",
                        "prompt already exists, keeping original; prompt_key={}",
                        safe_log_label(name)
                    );
                    return Ok(());
                }
                crate::DuplicateBehavior::Replace => {
                    log::debug!(
                        target: "fastmcp_rust::router",
                        "replacing prompt; prompt_key={}",
                        safe_log_label(name)
                    );
                    // Fall through to insert
                }
                crate::DuplicateBehavior::Ignore => {
                    return Ok(());
                }
            }
        }

        let final_definition = admit_final
            .then(|| admit_final_prompt_definition(&handler, &def))
            .transpose()?;
        self.prompts.insert(def.name.clone(), Box::new(handler));
        if legacy_enabled {
            self.final_only_prompts.remove(&def.name);
        } else {
            self.final_only_prompts.insert(def.name.clone());
        }
        match final_definition {
            Some(final_definition) => {
                self.final_prompts.insert(
                    def.name.clone(),
                    AdmittedFinalPromptRegistration {
                        definition: final_definition,
                        tags: def.tags.clone(),
                    },
                );
            }
            None => {
                self.final_prompts.remove(&def.name);
            }
        }
        if !existed {
            self.prompt_order.push(def.name);
        }
        Ok(())
    }

    /// Returns all tool definitions.
    #[must_use]
    pub fn tools(&self) -> Vec<Tool> {
        self.tool_order
            .iter()
            .filter_map(|name| self.tools.get(name))
            .filter(|entry| entry.legacy_enabled)
            .map(|entry| entry.definition.clone())
            .collect()
    }

    /// Returns tool definitions filtered by session state and tags.
    ///
    /// Tools that have been disabled in the session state will not be included.
    /// If tag filters are provided, tools must match the include/exclude criteria.
    #[must_use]
    pub fn tools_filtered(
        &self,
        session_state: Option<&SessionState>,
        tag_filters: Option<&TagFilters<'_>>,
    ) -> Vec<Tool> {
        self.tool_order
            .iter()
            .filter_map(|name| self.tools.get(name))
            .filter_map(|entry| {
                if !entry.legacy_enabled {
                    return None;
                }
                let def = &entry.definition;
                // Check session state filter
                if let Some(state) = session_state {
                    if !state.is_tool_enabled(&def.name) {
                        return None;
                    }
                }
                // Check tag filters
                if let Some(filters) = tag_filters {
                    if !filters.matches(&def.tags) {
                        return None;
                    }
                }
                Some(def.clone())
            })
            .collect()
    }

    /// Returns all resource definitions.
    #[must_use]
    pub fn resources(&self) -> Vec<Resource> {
        self.resource_order
            .iter()
            .filter_map(|uri| self.resources.get(uri))
            .filter(|handler| {
                let uri = handler.definition().uri;
                !self.final_only_resources.contains(&uri)
            })
            .map(|h| h.definition())
            .collect()
    }

    /// Returns resource definitions filtered by session state and tags.
    ///
    /// Resources that have been disabled in the session state will not be included.
    /// If tag filters are provided, resources must match the include/exclude criteria.
    #[must_use]
    pub fn resources_filtered(
        &self,
        session_state: Option<&SessionState>,
        tag_filters: Option<&TagFilters<'_>>,
    ) -> Vec<Resource> {
        self.resource_order
            .iter()
            .filter_map(|uri| self.resources.get(uri))
            .filter_map(|h| {
                let def = h.definition();
                if self.final_only_resources.contains(&def.uri) {
                    return None;
                }
                // Check session state filter
                if let Some(state) = session_state {
                    if !state.is_resource_enabled(&def.uri) {
                        return None;
                    }
                }
                // Check tag filters
                if let Some(filters) = tag_filters {
                    if !filters.matches(&def.tags) {
                        return None;
                    }
                }
                Some(def)
            })
            .collect()
    }

    /// Returns all resource templates.
    #[must_use]
    pub fn resource_templates(&self) -> Vec<ResourceTemplate> {
        self.resource_template_order
            .iter()
            .filter_map(|t| self.resource_templates.get(t))
            .filter(|entry| entry.legacy_enabled)
            .map(|entry| entry.template.clone())
            .collect()
    }

    /// Returns resource templates filtered by session state and tags.
    ///
    /// Templates that have been disabled in the session state will not be included.
    /// If tag filters are provided, templates must match the include/exclude criteria.
    #[must_use]
    pub fn resource_templates_filtered(
        &self,
        session_state: Option<&SessionState>,
        tag_filters: Option<&TagFilters<'_>>,
    ) -> Vec<ResourceTemplate> {
        self.resource_template_order
            .iter()
            .filter_map(|t| self.resource_templates.get(t))
            .filter_map(|entry| {
                if !entry.legacy_enabled {
                    return None;
                }
                // Check session state filter
                if let Some(state) = session_state {
                    if !state.is_resource_enabled(&entry.template.uri_template) {
                        return None;
                    }
                }
                // Check tag filters
                if let Some(filters) = tag_filters {
                    if !filters.matches(&entry.template.tags) {
                        return None;
                    }
                }
                Some(entry.template.clone())
            })
            .collect()
    }

    /// Returns all prompt definitions.
    #[must_use]
    pub fn prompts(&self) -> Vec<Prompt> {
        self.prompt_order
            .iter()
            .filter_map(|name| self.prompts.get(name))
            .filter(|handler| {
                let name = handler.definition().name;
                !self.final_only_prompts.contains(&name)
            })
            .map(|h| h.definition())
            .collect()
    }

    /// Returns prompt definitions filtered by session state and tags.
    ///
    /// Prompts that have been disabled in the session state will not be included.
    /// If tag filters are provided, prompts must match the include/exclude criteria.
    #[must_use]
    pub fn prompts_filtered(
        &self,
        session_state: Option<&SessionState>,
        tag_filters: Option<&TagFilters<'_>>,
    ) -> Vec<Prompt> {
        self.prompt_order
            .iter()
            .filter_map(|name| self.prompts.get(name))
            .filter_map(|h| {
                let def = h.definition();
                if self.final_only_prompts.contains(&def.name) {
                    return None;
                }
                // Check session state filter
                if let Some(state) = session_state {
                    if !state.is_prompt_enabled(&def.name) {
                        return None;
                    }
                }
                // Check tag filters
                if let Some(filters) = tag_filters {
                    if !filters.matches(&def.tags) {
                        return None;
                    }
                }
                Some(def)
            })
            .collect()
    }

    /// Returns the number of registered tools.
    #[must_use]
    pub fn tools_count(&self) -> usize {
        self.tools.len()
    }

    /// Returns the number of registered resources.
    #[must_use]
    pub fn resources_count(&self) -> usize {
        self.resources.len()
    }

    /// Returns the number of registered resource templates.
    #[must_use]
    pub fn resource_templates_count(&self) -> usize {
        self.resource_templates.len()
    }

    /// Returns the number of registered prompts.
    #[must_use]
    pub fn prompts_count(&self) -> usize {
        self.prompts.len()
    }

    /// Returns the immutable behavior registry for final server discovery.
    ///
    /// This records only APIs backed by this router's installed catalog. The
    /// The server composition supplies final subscription execution and
    /// publishes catalog/resource changes through its request-owned listener
    /// registry. This router records the catalog branches that can therefore
    /// be selected by those final filters; it still does not advertise the
    /// removed logging-request emitter.
    #[must_use]
    pub(crate) fn server_discovery_behavior_registry(&self) -> ServerBehaviorRegistry {
        let mut behaviors = Vec::with_capacity(11);
        behaviors.push(ServerBehavior::SubscriptionsListen);
        if self.final_completion_enabled {
            behaviors.push(ServerBehavior::CompletionComplete);
        }
        if self
            .tool_order
            .iter()
            .filter_map(|name| self.tools.get(name))
            .any(|entry| entry.final_registration.is_some())
        {
            behaviors.push(ServerBehavior::ToolsList);
            behaviors.push(ServerBehavior::ToolsListChangedNotification);
        }
        if !self.final_resources.is_empty()
            || self
                .resource_template_order
                .iter()
                .filter_map(|key| self.resource_templates.get(key))
                .any(|entry| entry.final_definition.is_some())
        {
            behaviors.push(ServerBehavior::ResourcesList);
            behaviors.push(ServerBehavior::ResourcesListChangedNotification);
        }
        if !self.final_resources.is_empty() {
            behaviors.push(ServerBehavior::ResourceUpdateDelivery);
        }
        if !self.final_prompts.is_empty() {
            behaviors.push(ServerBehavior::PromptsList);
            behaviors.push(ServerBehavior::PromptsListChangedNotification);
        }
        ServerBehaviorRegistry::from_behaviors(behaviors)
    }

    /// Gets a tool handler by name.
    #[must_use]
    pub fn get_tool(&self, name: &str) -> Option<&BoxedToolHandler> {
        self.tools.get(name).map(|entry| &entry.handler)
    }

    /// Gets a resource handler by URI.
    #[must_use]
    pub fn get_resource(&self, uri: &str) -> Option<&BoxedResourceHandler> {
        self.resources.get(uri)
    }

    /// Gets a resource template by URI template.
    #[must_use]
    pub fn get_resource_template(&self, uri_template: &str) -> Option<&ResourceTemplate> {
        self.resource_templates
            .get(uri_template)
            .map(|entry| &entry.template)
    }

    /// Returns true if a resource exists for the given URI (static or template match).
    #[must_use]
    pub fn resource_exists(&self, uri: &str) -> bool {
        self.resolve_resource(uri).is_some()
    }

    fn resolve_resource(&self, uri: &str) -> Option<ResolvedResource<'_>> {
        if let Some(handler) = self.resources.get(uri) {
            return Some(ResolvedResource {
                handler,
                params: UriParams::new(),
                final_enabled: self.final_resources.contains_key(uri),
                legacy_enabled: !self.final_only_resources.contains(uri),
            });
        }

        // Use pre-sorted template keys to avoid sorting on every lookup
        'templates: for key in &self.sorted_template_keys {
            let entry = &self.resource_templates[key];
            let Some(handler) = entry.handler.as_ref() else {
                continue;
            };
            let Some(values) = entry.matcher.match_uri(uri).ok().flatten() else {
                continue;
            };
            let mut params = UriParams::with_capacity(values.len());
            for (name, value) in values {
                let TemplateValue::Scalar(value) = value else {
                    continue 'templates;
                };
                params.insert(name, value);
            }
            return Some(ResolvedResource {
                handler,
                params,
                final_enabled: entry.final_definition.is_some(),
                legacy_enabled: entry.legacy_enabled,
            });
        }

        None
    }

    /// Gets a prompt handler by name.
    #[must_use]
    pub fn get_prompt(&self, name: &str) -> Option<&BoxedPromptHandler> {
        self.prompts.get(name)
    }

    // ========================================================================
    // Request Dispatch Methods
    // ========================================================================

    /// Handles the initialize request.
    pub fn handle_initialize(
        &self,
        request_ctx: &McpContext,
        session: &mut Session,
        params: InitializeParams,
        instructions: Option<&str>,
    ) -> McpResult<InitializeResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        debug!(
            target: targets::SESSION,
            "preparing session initialization; client_key={}",
            safe_log_label(&params.client_info.name)
        );

        // Initialize the session
        session.initialize(
            params.client_info,
            params.capabilities,
            PROTOCOL_VERSION.to_string(),
        );

        Ok(InitializeResult {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: session.server_capabilities().clone(),
            server_info: session.server_info().clone(),
            instructions: instructions.map(String::from),
        })
    }

    /// Dispatches one exact legacy `completion/complete` request.
    ///
    /// This route decodes through the dual-era core contract before invoking
    /// the installed handler. In particular, a final `_meta` object remains a
    /// cross-era error even though the legacy parameter shape is otherwise
    /// intentionally open.
    pub(crate) fn dispatch_legacy_completion(
        &self,
        request_ctx: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<serde_json::Value> {
        if request.method != COMPLETION_COMPLETE {
            return Err(McpError::method_not_found(&request.method));
        }

        let request = CoreRequest::decode(
            ProtocolEra::Legacy2024,
            COMPLETION_COMPLETE,
            request.params.as_ref(),
        )
        .map_err(|error| McpError::invalid_params(error.to_string()))?;
        let CoreRequest::Legacy(LegacyCoreRequest::Completion(params)) = request else {
            return Err(McpError::internal_error(
                "legacy completion dispatch selected another core request",
            ));
        };

        serde_json::to_value(self.handle_completion_legacy(request_ctx, params)?)
            .map_err(McpError::from)
    }

    /// Handles one exact MCP 2024-11-05 completion request.
    pub fn handle_completion_legacy(
        &self,
        request_ctx: &McpContext,
        params: LegacyCompletionParams,
    ) -> McpResult<LegacyCompletionResult> {
        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let handler = self
            .completion_handler
            .as_ref()
            .ok_or_else(|| McpError::method_not_found(COMPLETION_COMPLETE))?;
        let handler_ctx =
            derive_handler_context(request_ctx, None, None, None, ProtocolEra::Legacy2024);
        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "completion_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let handler_ctx = handler_ctx.with_operation_deadline(effective_budget.deadline);
        let outcome = run_handler(&handler_ctx, effective_budget, "completion", || {
            handler.complete_legacy_async(&handler_ctx, params)
        })?;

        let completion = match outcome {
            Outcome::Ok(completion) => completion,
            Outcome::Err(error) => {
                return Err(sanitize_handler_error(
                    request_ctx.cx(),
                    "completion",
                    error,
                ));
            }
            Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => {
                return Err(sanitized_handler_panic(request_ctx.cx(), "completion"));
            }
        };

        Ok(LegacyCompletionResult {
            completion,
            meta: None,
        })
    }

    async fn handle_completion_final_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: FinalCompletionParams,
    ) -> McpResult<FinalCompletionResult> {
        let dispatch_started_at = request_ctx.cx().now();
        if request_cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        if !self.final_completion_enabled {
            return Err(McpError::method_not_found(COMPLETION_COMPLETE));
        }

        match &params.reference {
            FinalCompletionReference::Prompt { name }
            | FinalCompletionReference::PromptWithTitle { name, .. }
                if !self.prompts.contains_key(name) =>
            {
                return Err(McpError::invalid_params(
                    "completion prompt reference is not registered",
                ));
            }
            FinalCompletionReference::Resource { uri }
                if !self.resources.contains_key(uri)
                    && !self.resource_templates.contains_key(uri) =>
            {
                return Err(McpError::invalid_params(
                    "completion resource reference is not registered",
                ));
            }
            FinalCompletionReference::Prompt { .. }
            | FinalCompletionReference::PromptWithTitle { .. }
            | FinalCompletionReference::Resource { .. } => {}
        }

        let handler = self
            .completion_handler
            .as_ref()
            .ok_or_else(|| McpError::method_not_found(COMPLETION_COMPLETE))?;
        let handler_ctx =
            derive_handler_context(request_ctx, None, None, None, ProtocolEra::Modern2026);
        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "completion_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let handler_ctx = handler_ctx.with_operation_deadline(effective_budget.deadline);
        let outcome = run_handler_in_request(
            &handler_ctx,
            request_cx,
            effective_budget,
            "completion",
            |child_cx| handler.complete_final_async_in_request(&handler_ctx, child_cx, params),
        )
        .await?;

        let completion = match outcome {
            Outcome::Ok(completion) => completion,
            Outcome::Err(error) => {
                return Err(sanitize_handler_error(
                    request_ctx.cx(),
                    "completion",
                    error,
                ));
            }
            Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => {
                return Err(sanitized_handler_panic(request_ctx.cx(), "completion"));
            }
        };

        Ok(FinalCompletionResult { completion })
    }

    /// Dispatches a request without connection or session state.
    ///
    /// This is the modern server-side routing seam. It deliberately has no
    /// `Session` argument: list results come from the immutable router catalog,
    /// and handler invocations receive a fresh state bag that cannot be shared
    /// with another request or connection. Every successful response is
    /// re-emitted through the final complete-result contract. State-bearing
    /// lifecycle methods and exact 2024-11-05 wire results stay on the legacy
    /// adapter rather than acquiring accidental modern semantics.
    pub(crate) fn dispatch_stateless(
        &self,
        request_ctx: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<serde_json::Value> {
        // The connection-oriented server adapter remains synchronous today.
        // Keep its ordered compatibility semantics here; modern runtime entry
        // points must use `dispatch_stateless_owned` below instead of sharing
        // this blocking bridge.
        block_on(self.dispatch_stateless_in_request(request_ctx, request_ctx.cx(), request))
    }

    /// Dispatches one modern request in a request-owned structured child task.
    ///
    /// The caller owns the returned future. It owns exactly one child task,
    /// waits for that task to finish, and cancellation of that wait aborts the
    /// child through `TaskHandle::join` before control returns. No task is
    /// detached: a result is produced only after the handler task has reached a
    /// terminal state. The child Cx is propagated to the modern handler hooks
    /// so their nested work remains in the same request lifetime.
    pub(crate) async fn dispatch_stateless_owned(
        self: Arc<Self>,
        request_ctx: McpContext,
        request: JsonRpcRequest,
    ) -> McpResult<serde_json::Value> {
        if let Some(error) = budget_error(&request_ctx) {
            return Err(error);
        }

        let join_cx = request_ctx.cx().clone();
        let dispatch_ctx = request_ctx.clone();
        let mut task = request_ctx
            .cx()
            .spawn(move |child_cx| async move {
                self.dispatch_stateless_in_request(&dispatch_ctx, &child_cx, &request)
                    .await
            })
            .map_err(|_error| {
                McpError::internal_error("request-owned modern dispatch could not be scheduled")
            })?;

        match task.join(&join_cx).await {
            Ok(result) => result,
            Err(asupersync::runtime::JoinError::Panicked(_payload)) => {
                Err(sanitized_handler_panic(&join_cx, "modern_dispatch"))
            }
            Err(_error) => Err(McpError::request_cancelled()),
        }
    }

    async fn dispatch_stateless_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        request: &JsonRpcRequest,
    ) -> McpResult<serde_json::Value> {
        if request_cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let params = request.params.as_ref();
        let result = match request.method.as_str() {
            // `ping` remains an exact 2024-11-05 connection method.  The
            // stateless endpoint is exclusively the final 2026 surface, so
            // accepting it here would make a legacy-only method appear in
            // final dispatch.
            "ping" => return Err(McpError::method_not_found("ping")),
            COMPLETION_COMPLETE => {
                let request =
                    CoreRequest::decode(ProtocolEra::Modern2026, COMPLETION_COMPLETE, params)
                        .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::Completion(params)) = request else {
                    return Err(McpError::internal_error(
                        "modern completion dispatch selected another core request",
                    ));
                };
                encode_stateless_handler_result(
                    self.handle_completion_final_in_request(request_ctx, request_cx, params)
                        .await,
                )?
            }
            "tools/list" => {
                let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/list", params)
                    .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::ToolsList(params)) = request else {
                    return Err(McpError::internal_error(
                        "modern tools/list dispatch selected another core request",
                    ));
                };
                encode_final_core_result(
                    self.handle_final_tools_list(request_ctx, params),
                    |result| FinalCoreResult::ToolsList {
                        result,
                        diagnostic: None,
                    },
                )?
            }
            "tools/call" => {
                self.admit_final_mrtr_response_map(params)?;
                let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", params)
                    .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::ToolsCall(params)) = request else {
                    return Err(McpError::internal_error(
                        "modern tools/call dispatch selected another core request",
                    ));
                };
                let binding = final_mrtr_binding(
                    request_ctx,
                    "tools/call",
                    params.name.clone(),
                    &params.arguments,
                )?;
                self.admit_final_tool_retry_metadata(&params)?;
                let resume_inputs = match self.resolve_final_mrtr_retry(
                    params.request_state.as_deref(),
                    params.input_responses.as_ref(),
                    binding.as_ref(),
                )? {
                    FinalMrtrDispatch::InputRequired(result) => result,
                    FinalMrtrDispatch::Fresh => {
                        self.dispatch_final_tools_call(
                            request_ctx,
                            request_cx,
                            params,
                            binding,
                            None,
                        )
                        .await?
                    }
                    FinalMrtrDispatch::Resume(resume_inputs) => {
                        self.dispatch_final_tools_call(
                            request_ctx,
                            request_cx,
                            params,
                            binding,
                            Some(resume_inputs),
                        )
                        .await?
                    }
                };
                resume_inputs
            }
            "resources/list" => {
                let request =
                    CoreRequest::decode(ProtocolEra::Modern2026, "resources/list", params)
                        .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::ResourcesList(params)) = &request else {
                    return Err(McpError::internal_error(
                        "modern resources/list dispatch selected another core request",
                    ));
                };
                encode_final_core_result(
                    self.handle_final_resources_list(request_ctx, params.clone()),
                    |result| FinalCoreResult::ResourcesList {
                        result,
                        diagnostic: None,
                    },
                )?
            }
            "resources/templates/list" => {
                let request = CoreRequest::decode(
                    ProtocolEra::Modern2026,
                    "resources/templates/list",
                    params,
                )
                .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::ResourceTemplatesList(params)) = &request
                else {
                    return Err(McpError::internal_error(
                        "modern resources/templates/list dispatch selected another core request",
                    ));
                };
                encode_final_core_result(
                    self.handle_final_resource_templates_list(request_ctx, params.clone()),
                    |result| FinalCoreResult::ResourceTemplatesList {
                        result,
                        diagnostic: None,
                    },
                )?
            }
            "resources/read" => {
                self.admit_final_mrtr_response_map(params)?;
                let request =
                    CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", params)
                        .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::ResourcesRead(params)) = &request else {
                    return Err(McpError::internal_error(
                        "modern resources/read dispatch selected another core request",
                    ));
                };
                let binding = final_mrtr_binding(
                    request_ctx,
                    "resources/read",
                    params.uri.as_str().to_owned(),
                    &(),
                )?;
                match self.resolve_final_mrtr_retry(
                    params.request_state.as_deref(),
                    params.input_responses.as_ref(),
                    binding.as_ref(),
                )? {
                    FinalMrtrDispatch::InputRequired(result) => result,
                    FinalMrtrDispatch::Fresh => {
                        self.dispatch_final_resources_read(
                            request_ctx,
                            request_cx,
                            params.clone(),
                            binding,
                            None,
                        )
                        .await?
                    }
                    FinalMrtrDispatch::Resume(resume_inputs) => {
                        self.dispatch_final_resources_read(
                            request_ctx,
                            request_cx,
                            params.clone(),
                            binding,
                            Some(resume_inputs),
                        )
                        .await?
                    }
                }
            }
            "prompts/list" => {
                let request = CoreRequest::decode(ProtocolEra::Modern2026, "prompts/list", params)
                    .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::PromptsList(params)) = &request else {
                    return Err(McpError::internal_error(
                        "modern prompts/list dispatch selected another core request",
                    ));
                };
                encode_final_core_result(
                    self.handle_final_prompts_list(request_ctx, params.clone()),
                    |result| FinalCoreResult::PromptsList {
                        result,
                        diagnostic: None,
                    },
                )?
            }
            "prompts/get" => {
                self.admit_final_mrtr_response_map(params)?;
                let request = CoreRequest::decode(ProtocolEra::Modern2026, "prompts/get", params)
                    .map_err(|error| McpError::invalid_params(error.to_string()))?;
                let CoreRequest::Final(FinalCoreRequest::PromptsGet(params)) = request else {
                    return Err(McpError::internal_error(
                        "modern prompts/get dispatch selected another core request",
                    ));
                };
                let binding = final_mrtr_binding(
                    request_ctx,
                    "prompts/get",
                    params.name.clone(),
                    &params.arguments,
                )?;
                match self.resolve_final_mrtr_retry(
                    params.request_state.as_deref(),
                    params.input_responses.as_ref(),
                    binding.as_ref(),
                )? {
                    FinalMrtrDispatch::InputRequired(result) => result,
                    FinalMrtrDispatch::Fresh => {
                        self.dispatch_final_prompts_get(
                            request_ctx,
                            request_cx,
                            params,
                            binding,
                            None,
                        )
                        .await?
                    }
                    FinalMrtrDispatch::Resume(resume_inputs) => {
                        self.dispatch_final_prompts_get(
                            request_ctx,
                            request_cx,
                            params,
                            binding,
                            Some(resume_inputs),
                        )
                        .await?
                    }
                }
            }
            _ => return Err(McpError::method_not_found(&request.method)),
        };

        if request_cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        Ok(result)
    }

    /// Admits bounded raw retry values before final parameter decoding clones
    /// them into method-specific fields or materializes `inputResponses`.
    fn admit_final_mrtr_response_map(&self, params: Option<&serde_json::Value>) -> McpResult<()> {
        let Some(params) = params else {
            return Ok(());
        };
        admit_mrtr_raw_json_value(params, MAX_MRTR_RAW_PARAMS_BYTES)?;
        let Some(input_responses) = params
            .as_object()
            .and_then(|members| members.get("inputResponses"))
        else {
            return Ok(());
        };
        admit_mrtr_raw_json_value(input_responses, MAX_MRTR_RAW_INPUT_RESPONSES_BYTES)?;
        let Some(input_responses) = input_responses.as_object() else {
            return Ok(());
        };
        if input_responses.len() > self.mrtr_exchanges.max_inputs_per_round() {
            return Err(McpError::invalid_params(
                "MRTR inputResponses exceeds the configured bound",
            ));
        }
        Ok(())
    }

    /// Verifies operation-relevant normalized metadata before an MRTR retry
    /// consumes its continuation. A task-capable tool performs capability and
    /// runtime readiness admission after normal dispatch too, but doing that
    /// only after state resolution would let altered retry metadata burn a
    /// valid state.
    fn admit_final_tool_retry_metadata(&self, params: &FinalCallToolParams) -> McpResult<()> {
        if params.request_state.is_none() || params.input_responses.is_none() {
            return Ok(());
        }
        let Some(final_registration) = self
            .tools
            .get(&params.name)
            .and_then(|entry| entry.final_registration.as_ref())
        else {
            return Ok(());
        };
        if final_registration.declares_final_tasks {
            self.admit_final_task_tool(&params.meta)?;
        }
        Ok(())
    }

    fn admit_final_task_tool(&self, metadata: &OpenMetadata) -> McpResult<()> {
        require_final_tasks_capability(metadata)?;
        let runtime = self.final_task_runtime.as_ref().ok_or_else(|| {
            McpError::internal_error("task-capable tool requires an installed final Tasks runtime")
        })?;
        runtime.ensure_task_service_ready()
    }

    fn issue_final_mrtr_input_required(
        &self,
        binding: MrtrExchangeBinding,
        handler_result: InputRequiredResult,
    ) -> McpResult<serde_json::Value> {
        // The handler may describe the input it needs, but it never controls
        // requestState. Its former state member and open result siblings are
        // intentionally not forwarded across this framework boundary.
        let input_requests = handler_mrtr_input_requests(&handler_result)?;
        let required = self.mrtr_exchanges.issue_bound(
            fastmcp_core::McpRequestCancellation::new(),
            binding,
            input_requests,
        )?;
        encode_mrtr_input_required_result(required)
    }

    /// Resolves a final embedded-input retry before its method handler runs.
    ///
    /// Only a framework-issued state whose immutable operation binding still
    /// matches may yield resume inputs. A complete retry passes those typed
    /// values into the handler's resume-aware final hook exactly once.
    fn resolve_final_mrtr_retry(
        &self,
        request_state: Option<&str>,
        input_responses: Option<&BTreeMap<String, serde_json::Value>>,
        binding: Option<&MrtrExchangeBinding>,
    ) -> McpResult<FinalMrtrDispatch> {
        match (request_state, input_responses) {
            (None, None) => Ok(FinalMrtrDispatch::Fresh),
            (Some(request_state), Some(input_responses)) => {
                let binding = binding.ok_or_else(|| {
                    McpError::invalid_params("MRTR retries require session state")
                })?;
                match self.mrtr_exchanges.accept_wire_bound(
                    request_state,
                    binding,
                    input_responses,
                )? {
                    MrtrRetry::Complete(inputs) => Ok(FinalMrtrDispatch::Resume(inputs)),
                    MrtrRetry::InputRequired(result) => encode_mrtr_input_required_result(result)
                        .map(FinalMrtrDispatch::InputRequired),
                }
            }
            _ => Err(McpError::invalid_params(
                "final MRTR retries require both inputResponses and requestState",
            )),
        }
    }

    async fn dispatch_final_tools_call(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: FinalCallToolParams,
        binding: Option<MrtrExchangeBinding>,
        resume_inputs: Option<MrtrCompletedInputs>,
    ) -> McpResult<serde_json::Value> {
        let request_metadata = params.meta.clone();
        let outcome = self
            .handle_tools_call_final_in_request(
                request_ctx,
                request_cx,
                params,
                SessionState::new(),
                None,
                None,
                resume_inputs.as_ref(),
            )
            .await?;
        match outcome {
            FinalToolOutcome::Complete(result) => encode_final_tools_call_result(Ok(result)),
            FinalToolOutcome::InputRequired(result) => {
                let binding = binding.ok_or_else(|| {
                    McpError::internal_error(
                        "MRTR input_required requires session state to bind retries",
                    )
                })?;
                self.issue_final_mrtr_input_required(binding, result)
            }
            FinalToolOutcome::CreateTask {
                work_descriptor,
                status_message,
            } => {
                require_final_tasks_capability(&request_metadata)?;
                let runtime = self.final_task_runtime.as_ref().ok_or_else(|| {
                    McpError::internal_error(
                        "task-capable tool requires an installed final Tasks runtime",
                    )
                })?;
                encode_final_task_result(
                    runtime.create_task_with_work(work_descriptor, status_message)?,
                )
            }
        }
    }

    async fn dispatch_final_resources_read(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: FinalReadResourceParams,
        binding: Option<MrtrExchangeBinding>,
        resume_inputs: Option<MrtrCompletedInputs>,
    ) -> McpResult<serde_json::Value> {
        match self
            .handle_resources_read_final_in_request(
                request_ctx,
                request_cx,
                params,
                SessionState::new(),
                None,
                None,
                resume_inputs.as_ref(),
            )
            .await?
        {
            FinalMethodOutcome::Complete(result) => encode_final_resources_read_result(Ok(result)),
            FinalMethodOutcome::InputRequired(result) => {
                let binding = binding.ok_or_else(|| {
                    McpError::internal_error(
                        "MRTR input_required requires session state to bind retries",
                    )
                })?;
                self.issue_final_mrtr_input_required(binding, result)
            }
        }
    }

    async fn dispatch_final_prompts_get(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: FinalGetPromptParams,
        binding: Option<MrtrExchangeBinding>,
        resume_inputs: Option<MrtrCompletedInputs>,
    ) -> McpResult<serde_json::Value> {
        match self
            .handle_prompts_get_final_in_request(
                request_ctx,
                request_cx,
                params,
                SessionState::new(),
                None,
                None,
                resume_inputs.as_ref(),
            )
            .await?
        {
            FinalMethodOutcome::Complete(result) => encode_final_prompts_get_result(Ok(result)),
            FinalMethodOutcome::InputRequired(result) => {
                let binding = binding.ok_or_else(|| {
                    McpError::internal_error(
                        "MRTR input_required requires session state to bind retries",
                    )
                })?;
                self.issue_final_mrtr_input_required(binding, result)
            }
        }
    }

    /// Handles the tools/list request.
    ///
    /// If session_state is provided, disabled tools will be filtered out.
    /// If include_tags/exclude_tags are provided, tools are filtered by tags.
    pub fn handle_tools_list(
        &self,
        request_ctx: &McpContext,
        params: ListToolsParams,
        session_state: Option<&SessionState>,
    ) -> McpResult<ListToolsResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let tag_filters =
            TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let tag_filters = if params.include_tags.is_some() || params.exclude_tags.is_some() {
            Some(&tag_filters)
        } else {
            None
        };
        let tools =
            crate::catch_extension_unwind(|| self.tools_filtered(session_state, tag_filters))
                .map_err(|_payload| sanitized_handler_panic(request_ctx.cx(), "tool_definition"))?;
        let Some(page_size) = self.list_page_size else {
            return Ok(ListToolsResult {
                tools,
                next_cursor: None,
            });
        };

        let offset = decode_cursor_offset(params.cursor.as_deref())?;
        let end = offset.saturating_add(page_size).min(tools.len());
        let next_cursor = if end < tools.len() {
            Some(encode_cursor_offset(end))
        } else {
            None
        };
        Ok(ListToolsResult {
            tools: tools.get(offset..end).unwrap_or_default().to_vec(),
            next_cursor,
        })
    }

    /// Handles a final tools/list request using only final-admitted entries.
    /// Normal registration admits schemas before committing its handler, so a
    /// malformed candidate cannot influence a modern catalog page or cursor.
    fn handle_final_tools_list(
        &self,
        request_ctx: &McpContext,
        params: FinalListParams,
    ) -> McpResult<FinalListToolsResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let tag_filters =
            TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let tag_filters = if params.include_tags.is_some() || params.exclude_tags.is_some() {
            Some(&tag_filters)
        } else {
            None
        };
        let tools = crate::catch_extension_unwind(|| {
            self.tool_order
                .iter()
                .filter_map(|name| self.tools.get(name))
                .filter(|entry| entry.final_registration.is_some())
                .map(|entry| entry.definition.clone())
                .filter(|tool| tag_filters.is_none_or(|filters| filters.matches(&tool.tags)))
                .collect::<Vec<_>>()
        })
        .map_err(|_payload| sanitized_handler_panic(request_ctx.cx(), "tool_definition"))?;

        let result = if let Some(page_size) = self.list_page_size {
            let offset = decode_cursor_offset(params.cursor.as_deref())?;
            let end = offset.saturating_add(page_size).min(tools.len());
            ListToolsResult {
                tools: tools.get(offset..end).unwrap_or_default().to_vec(),
                next_cursor: (end < tools.len()).then(|| encode_cursor_offset(end)),
            }
        } else {
            ListToolsResult {
                tools,
                next_cursor: None,
            }
        };
        self.project_final_tools_list(request_ctx, result, self.final_cache_hints)
    }

    fn project_final_tools_list(
        &self,
        _request_ctx: &McpContext,
        result: ListToolsResult,
        cache_hints: FinalCacheHintPolicy,
    ) -> McpResult<FinalListToolsResult> {
        let tools = result
            .tools
            .into_iter()
            .map(|tool| {
                let entry = self.tools.get(&tool.name).ok_or_else(|| {
                    McpError::internal_error("listed tool is absent from the router catalog")
                })?;
                let final_registration = entry.final_registration.as_ref().ok_or_else(|| {
                    McpError::internal_error(
                        "legacy-only tool reached the final catalog projection",
                    )
                })?;

                Ok(final_registration.final_definition.clone())
            })
            .collect::<McpResult<Vec<_>>>()?;
        Ok(FinalListToolsResult {
            tools,
            next_cursor: result.next_cursor,
            ttl_ms: cache_hints.list_ttl_ms,
            cache_scope: cache_hints.scope,
        })
    }

    fn handle_final_resources_list(
        &self,
        request_ctx: &McpContext,
        params: FinalListParams,
    ) -> McpResult<FinalListResourcesResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        let filters = TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let filters =
            (params.include_tags.is_some() || params.exclude_tags.is_some()).then_some(filters);
        let resources = self
            .resource_order
            .iter()
            .filter_map(|uri| self.final_resources.get(uri))
            .filter(|entry| {
                filters
                    .as_ref()
                    .is_none_or(|filters| filters.matches(&entry.tags))
            })
            .map(|entry| entry.definition.clone())
            .collect();
        let (resources, next_cursor) =
            page_final_catalog(resources, params.cursor.as_deref(), self.list_page_size)?;
        Ok(FinalListResourcesResult {
            resources,
            next_cursor,
            ttl_ms: self.final_cache_hints.list_ttl_ms,
            cache_scope: self.final_cache_hints.scope,
        })
    }

    fn handle_final_resource_templates_list(
        &self,
        request_ctx: &McpContext,
        params: FinalListParams,
    ) -> McpResult<FinalListResourceTemplatesResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        let filters = TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let filters =
            (params.include_tags.is_some() || params.exclude_tags.is_some()).then_some(filters);
        let resource_templates = self
            .resource_template_order
            .iter()
            .filter_map(|key| self.resource_templates.get(key))
            .filter_map(|entry| {
                entry
                    .final_definition
                    .as_ref()
                    .map(|definition| (definition, &entry.template.tags))
            })
            .filter(|(_, tags)| filters.as_ref().is_none_or(|filters| filters.matches(tags)))
            .map(|(definition, _)| definition.clone())
            .collect();
        let (resource_templates, next_cursor) = page_final_catalog(
            resource_templates,
            params.cursor.as_deref(),
            self.list_page_size,
        )?;
        Ok(FinalListResourceTemplatesResult {
            resource_templates,
            next_cursor,
            ttl_ms: self.final_cache_hints.list_ttl_ms,
            cache_scope: self.final_cache_hints.scope,
        })
    }

    fn handle_final_prompts_list(
        &self,
        request_ctx: &McpContext,
        params: FinalListParams,
    ) -> McpResult<FinalListPromptsResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        let filters = TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let filters =
            (params.include_tags.is_some() || params.exclude_tags.is_some()).then_some(filters);
        let prompts = self
            .prompt_order
            .iter()
            .filter_map(|name| self.final_prompts.get(name))
            .filter(|entry| {
                filters
                    .as_ref()
                    .is_none_or(|filters| filters.matches(&entry.tags))
            })
            .map(|entry| entry.definition.clone())
            .collect();
        let (prompts, next_cursor) =
            page_final_catalog(prompts, params.cursor.as_deref(), self.list_page_size)?;
        Ok(FinalListPromptsResult {
            prompts,
            next_cursor,
            ttl_ms: self.final_cache_hints.list_ttl_ms,
            cache_scope: self.final_cache_hints.scope,
        })
    }

    /// Handles the tools/call request.
    ///
    /// # Arguments
    ///
    /// * `request_ctx` - Request authority for cancellation, identity, auth, and accounting
    /// * `params` - The tool call parameters including tool name and arguments
    /// * `session_state` - Session state for per-session storage
    /// * `notification_sender` - Optional callback for sending progress notifications
    /// * `bidirectional_senders` - Optional senders for sampling/elicitation
    pub fn handle_tools_call(
        &self,
        request_ctx: &McpContext,
        params: CallToolParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<CallToolResult> {
        debug!(
            target: targets::HANDLER,
            "calling tool; tool_key={}; arguments_present={}",
            safe_log_label(&params.name),
            params.arguments.is_some()
        );

        // Anchor every relative ceiling once at dispatch entry. Definition/schema
        // work and timeout metadata lookup are part of this operation and must
        // not reset a handler-declared window by taking a later clock sample.
        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        // Check if tool is disabled for this session
        if !session_state.is_tool_enabled(&params.name) {
            return Err(McpError::new(
                McpErrorCode::MethodNotFound,
                format!("Tool '{}' is disabled for this session", params.name),
            ));
        }

        // Find the tool handler
        let entry = self
            .tools
            .get(&params.name)
            .ok_or_else(|| McpError::method_not_found(&format!("tool: {}", params.name)))?;
        if !entry.legacy_enabled {
            return Err(McpError::method_not_found(&format!(
                "tool: {}",
                params.name
            )));
        }
        let handler = &entry.handler;

        // Validate arguments against the tool's input schema
        // Default to empty object since MCP tool arguments are always objects
        let arguments = params.arguments.unwrap_or_else(|| serde_json::json!({}));
        // Use strict or lenient validation based on configuration
        let validation_result = if self.strict_input_validation {
            validate_strict(&entry.definition.input_schema, &arguments)
        } else {
            validate(&entry.definition.input_schema, &arguments)
        };

        if let Err(validation_errors) = validation_result {
            let error_messages: Vec<String> = validation_errors
                .iter()
                .map(|e| format!("{}: {}", e.path, e.message))
                .collect();
            return Err(McpError::invalid_params(format!(
                "Input validation failed: {}",
                error_messages.join("; ")
            )));
        }

        // Extract progress marker from request metadata
        let progress_marker: Option<ProgressMarker> =
            params.meta.as_ref().and_then(|m| m.progress_marker.clone());

        // Clone the request authority so auth, budget accounting, cancellation,
        // and mask state remain shared with middleware and nested operations.
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
            ProtocolEra::Legacy2024,
        );

        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "tool_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);

        // Call the handler asynchronously - returns McpOutcome (4-valued)
        let outcome = run_handler(&ctx, effective_budget, "tool", || {
            handler.call_async(&ctx, arguments)
        })?;
        match outcome {
            Outcome::Ok(content) => Ok(CallToolResult {
                content: legacy_contents_from_handler(content)?,
                is_error: false,
                meta: None,
                additional: BTreeMap::new(),
            }),
            Outcome::Err(e) => {
                let e = sanitize_handler_error(request_ctx.cx(), "tool", e);
                if is_framework_terminal_tool_error(e.code) {
                    return Err(e);
                }

                // Tool errors are returned as content with is_error=true
                Ok(CallToolResult {
                    content: vec![LegacyContent::Text {
                        text: e.message,
                        annotations: None,
                        additional: BTreeMap::new(),
                    }],
                    is_error: true,
                    meta: None,
                    additional: BTreeMap::new(),
                })
            }
            Outcome::Cancelled(_) => {
                // Cancelled requests are reported as JSON-RPC errors
                Err(McpError::request_cancelled())
            }
            Outcome::Panicked(_payload) => Err(sanitized_handler_panic(request_ctx.cx(), "tool")),
        }
    }

    async fn handle_tools_call_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: CallToolParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<CallToolResult> {
        debug!(
            target: targets::HANDLER,
            "calling modern tool; tool_key={}; arguments_present={}",
            safe_log_label(&params.name),
            params.arguments.is_some()
        );

        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        if !session_state.is_tool_enabled(&params.name) {
            return Err(McpError::new(
                McpErrorCode::MethodNotFound,
                format!("Tool '{}' is disabled for this session", params.name),
            ));
        }

        let entry = self
            .tools
            .get(&params.name)
            .ok_or_else(|| McpError::method_not_found(&format!("tool: {}", params.name)))?;
        if !entry.legacy_enabled {
            return Err(McpError::method_not_found(&format!(
                "tool: {}",
                params.name
            )));
        }
        let handler = &entry.handler;
        let arguments = params.arguments.unwrap_or_else(|| serde_json::json!({}));
        let validation_result = if self.strict_input_validation {
            validate_strict(&entry.definition.input_schema, &arguments)
        } else {
            validate(&entry.definition.input_schema, &arguments)
        };
        if let Err(validation_errors) = validation_result {
            let error_messages: Vec<String> = validation_errors
                .iter()
                .map(|error| format!("{}: {}", error.path, error.message))
                .collect();
            return Err(McpError::invalid_params(format!(
                "Input validation failed: {}",
                error_messages.join("; ")
            )));
        }

        let progress_marker = params
            .meta
            .as_ref()
            .and_then(|meta| meta.progress_marker.clone());
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
            ProtocolEra::Legacy2024,
        );
        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "tool_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);
        let outcome =
            run_handler_in_request(&ctx, request_cx, effective_budget, "tool", |child_cx| {
                handler.call_async_in_request(&ctx, child_cx, arguments)
            })
            .await?;

        match outcome {
            Outcome::Ok(content) => Ok(CallToolResult {
                content: legacy_contents_from_handler(content)?,
                is_error: false,
                meta: None,
                additional: BTreeMap::new(),
            }),
            Outcome::Err(error) => {
                let error = sanitize_handler_error(request_ctx.cx(), "tool", error);
                if is_framework_terminal_tool_error(error.code) {
                    return Err(error);
                }
                Ok(CallToolResult {
                    content: vec![LegacyContent::Text {
                        text: error.message,
                        annotations: None,
                        additional: BTreeMap::new(),
                    }],
                    is_error: true,
                    meta: None,
                    additional: BTreeMap::new(),
                })
            }
            Outcome::Cancelled(_) => Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => Err(sanitized_handler_panic(request_ctx.cx(), "tool")),
        }
    }

    /// Handles one final MCP 2026-07-28 `tools/call` request.
    ///
    /// Legacy dispatch remains on [`Self::handle_tools_call`], including its
    /// exact `CallToolResult` behavior. Final dispatch calls the final handler
    /// hook directly and encodes the returned complete result with the typed
    /// core result codec.
    async fn handle_tools_call_final_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: FinalCallToolParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
        resume_inputs: Option<&MrtrCompletedInputs>,
    ) -> McpResult<FinalToolOutcome> {
        debug!(
            target: targets::HANDLER,
            "calling final tool; tool_key={}; arguments_present={}",
            safe_log_label(&params.name),
            !params.arguments.is_absent()
        );

        let dispatch_started_at = request_ctx.cx().now();
        if request_cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        let progress_marker = final_progress_marker(&params.meta)?;
        if !session_state.is_tool_enabled(&params.name) {
            return Err(McpError::new(
                McpErrorCode::MethodNotFound,
                format!("Tool '{}' is disabled for this session", params.name),
            ));
        }

        let entry = self
            .tools
            .get(&params.name)
            .ok_or_else(|| McpError::invalid_params(format!("Unknown tool: {}", params.name)))?;
        let final_registration = entry
            .final_registration
            .as_ref()
            .ok_or_else(|| McpError::invalid_params(format!("Unknown tool: {}", params.name)))?;
        let handler = &entry.handler;
        let input_schema = &final_registration.schemas.input;
        let output_schema = final_registration.schemas.output.as_ref();
        if params.arguments.is_explicit_null() {
            return Err(McpError::invalid_params(
                "tools/call arguments must not be null",
            ));
        }
        let declares_final_tasks = final_registration.declares_final_tasks;
        if declares_final_tasks {
            self.admit_final_task_tool(&params.meta)?;
        }
        let arguments = params
            .arguments
            .into_value()
            .unwrap_or_else(|| serde_json::json!({}));
        if input_schema.validate(&arguments).is_err() {
            let mut result = crate::handler::promote_legacy_tool_content(vec![Content::text(
                "Tool arguments do not match the declared input schema.",
            )])?;
            result.payload.is_error = true;
            result.payload.structured_content = final_registration
                .schemas
                .errors
                .as_ref()
                .map(|errors| errors.input_validation.clone());
            return Ok(FinalToolOutcome::Complete(result));
        }

        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
            ProtocolEra::Modern2026,
        );
        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "tool_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);
        let outcome =
            run_handler_in_request(&ctx, request_cx, effective_budget, "tool", |child_cx| {
                if let Some(resume_inputs) = resume_inputs {
                    handler.call_final_outcome_async_resuming_in_request(
                        &ctx,
                        child_cx,
                        arguments,
                        Some(resume_inputs),
                    )
                } else {
                    handler.call_final_outcome_async_in_request(&ctx, child_cx, arguments)
                }
            })
            .await?;

        match outcome {
            Outcome::Ok(result) => {
                match &result {
                    FinalToolOutcome::Complete(result) => {
                        if let Some(output_schema) = output_schema {
                            let structured_content = result
                                .payload
                                .structured_content
                                .as_ref()
                                .ok_or_else(|| {
                                    McpError::internal_error(
                                        "tool output is missing structuredContent required by the declared output schema",
                                    )
                                })?;
                            if output_schema.validate(structured_content).is_err() {
                                return Err(McpError::internal_error(
                                    "tool output does not match the declared output schema",
                                ));
                            }
                        }
                    }
                    FinalToolOutcome::CreateTask { .. } if !declares_final_tasks => {
                        return Err(McpError::invalid_request(
                            "tool returned CreateTask without declaring final Tasks capability",
                        ));
                    }
                    FinalToolOutcome::InputRequired(_) | FinalToolOutcome::CreateTask { .. } => {}
                }
                Ok(result)
            }
            Outcome::Err(error) => {
                let error = sanitize_handler_error(request_ctx.cx(), "tool", error);
                if is_framework_terminal_tool_error(error.code) {
                    return Err(error);
                }
                let mut result =
                    crate::handler::promote_legacy_tool_content(vec![Content::Text {
                        text: error.message,
                    }])?;
                result.payload.is_error = true;
                result.payload.structured_content = final_registration
                    .schemas
                    .errors
                    .as_ref()
                    .map(|errors| errors.handler.clone());
                Ok(FinalToolOutcome::Complete(result))
            }
            Outcome::Cancelled(_) => Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => Err(sanitized_handler_panic(request_ctx.cx(), "tool")),
        }
    }

    /// Handles the resources/list request.
    ///
    /// If session_state is provided, disabled resources will be filtered out.
    /// If include_tags/exclude_tags are provided, resources are filtered by tags.
    pub fn handle_resources_list(
        &self,
        request_ctx: &McpContext,
        params: ListResourcesParams,
        session_state: Option<&SessionState>,
    ) -> McpResult<ListResourcesResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let tag_filters =
            TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let tag_filters = if params.include_tags.is_some() || params.exclude_tags.is_some() {
            Some(&tag_filters)
        } else {
            None
        };
        let resources = crate::catch_extension_unwind(|| {
            self.resources_filtered(session_state, tag_filters)
        })
        .map_err(|_payload| sanitized_handler_panic(request_ctx.cx(), "resource_definition"))?;
        let Some(page_size) = self.list_page_size else {
            return Ok(ListResourcesResult {
                resources,
                next_cursor: None,
            });
        };

        let offset = decode_cursor_offset(params.cursor.as_deref())?;
        let end = offset.saturating_add(page_size).min(resources.len());
        let next_cursor = if end < resources.len() {
            Some(encode_cursor_offset(end))
        } else {
            None
        };
        Ok(ListResourcesResult {
            resources: resources.get(offset..end).unwrap_or_default().to_vec(),
            next_cursor,
        })
    }

    /// Handles the resources/templates/list request.
    ///
    /// If session_state is provided, disabled resource templates will be filtered out.
    /// If include_tags/exclude_tags are provided, templates are filtered by tags.
    pub fn handle_resource_templates_list(
        &self,
        request_ctx: &McpContext,
        params: ListResourceTemplatesParams,
        session_state: Option<&SessionState>,
    ) -> McpResult<ListResourceTemplatesResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let tag_filters =
            TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let tag_filters = if params.include_tags.is_some() || params.exclude_tags.is_some() {
            Some(&tag_filters)
        } else {
            None
        };
        let templates = self.resource_templates_filtered(session_state, tag_filters);
        let Some(page_size) = self.list_page_size else {
            return Ok(ListResourceTemplatesResult {
                resource_templates: templates,
                next_cursor: None,
            });
        };

        let offset = decode_cursor_offset(params.cursor.as_deref())?;
        let end = offset.saturating_add(page_size).min(templates.len());
        let next_cursor = if end < templates.len() {
            Some(encode_cursor_offset(end))
        } else {
            None
        };
        Ok(ListResourceTemplatesResult {
            resource_templates: templates.get(offset..end).unwrap_or_default().to_vec(),
            next_cursor,
        })
    }

    /// Handles the resources/read request.
    ///
    /// # Arguments
    ///
    /// * `request_ctx` - Request authority for cancellation, identity, auth, and accounting
    /// * `params` - The resource read parameters including URI
    /// * `session_state` - Session state for per-session storage
    /// * `notification_sender` - Optional callback for sending progress notifications
    /// * `bidirectional_senders` - Optional senders for sampling/elicitation
    pub fn handle_resources_read(
        &self,
        request_ctx: &McpContext,
        params: &ReadResourceParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<ReadResourceResult> {
        debug!(
            target: targets::HANDLER,
            "reading resource; resource_key={}",
            safe_log_label(&params.uri)
        );

        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        // Check if resource is disabled for this session
        if !session_state.is_resource_enabled(&params.uri) {
            return Err(McpError::new(
                McpErrorCode::ResourceNotFound,
                format!("Resource '{}' is disabled for this session", params.uri),
            ));
        }

        let resolved = self
            .resolve_resource(&params.uri)
            .ok_or_else(|| McpError::resource_not_found(&params.uri))?;
        if !resolved.legacy_enabled {
            return Err(McpError::resource_not_found(&params.uri));
        }

        // Extract progress marker from request metadata
        let progress_marker: Option<ProgressMarker> =
            params.meta.as_ref().and_then(|m| m.progress_marker.clone());

        // Clone the request authority so auth, budget accounting, cancellation,
        // and mask state remain shared with middleware and nested operations.
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
            ProtocolEra::Legacy2024,
        );

        let handler_timeout = read_handler_timeout(request_ctx.cx(), "resource_timeout", || {
            resolved.handler.timeout()
        })?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);

        // Read the resource asynchronously - returns McpOutcome (4-valued)
        let outcome = run_handler(&ctx, effective_budget, "resource", || {
            resolved
                .handler
                .read_async_with_uri(&ctx, &params.uri, &resolved.params)
        })?;

        // Convert 4-valued Outcome to McpResult for JSON-RPC response
        let contents = match outcome {
            Outcome::Ok(contents) => contents,
            Outcome::Err(error) => {
                return Err(sanitize_handler_error(request_ctx.cx(), "resource", error));
            }
            Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => {
                return Err(sanitized_handler_panic(request_ctx.cx(), "resource"));
            }
        };

        Ok(ReadResourceResult {
            contents: legacy_resource_contents_from_handler(contents)?,
            meta: None,
            additional: BTreeMap::new(),
        })
    }

    async fn handle_resources_read_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: &ReadResourceParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<ReadResourceResult> {
        debug!(
            target: targets::HANDLER,
            "reading modern resource; resource_key={}",
            safe_log_label(&params.uri)
        );

        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        if !session_state.is_resource_enabled(&params.uri) {
            return Err(McpError::new(
                McpErrorCode::ResourceNotFound,
                format!("Resource '{}' is disabled for this session", params.uri),
            ));
        }

        let resolved = self
            .resolve_resource(&params.uri)
            .ok_or_else(|| McpError::resource_not_found(&params.uri))?;
        if !resolved.legacy_enabled {
            return Err(McpError::resource_not_found(&params.uri));
        }
        let progress_marker = params
            .meta
            .as_ref()
            .and_then(|meta| meta.progress_marker.clone());
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
            ProtocolEra::Legacy2024,
        );
        let handler_timeout = read_handler_timeout(request_ctx.cx(), "resource_timeout", || {
            resolved.handler.timeout()
        })?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);
        let outcome =
            run_handler_in_request(&ctx, request_cx, effective_budget, "resource", |child_cx| {
                resolved.handler.read_async_with_uri_in_request(
                    &ctx,
                    child_cx,
                    &params.uri,
                    &resolved.params,
                )
            })
            .await?;

        let contents = match outcome {
            Outcome::Ok(contents) => contents,
            Outcome::Err(error) => {
                return Err(sanitize_handler_error(request_ctx.cx(), "resource", error));
            }
            Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => {
                return Err(sanitized_handler_panic(request_ctx.cx(), "resource"));
            }
        };

        Ok(ReadResourceResult {
            contents: legacy_resource_contents_from_handler(contents)?,
            meta: None,
            additional: BTreeMap::new(),
        })
    }

    /// Handles one final MCP 2026-07-28 `resources/read` request.
    ///
    /// Legacy dispatch remains on [`Self::handle_resources_read`], including
    /// its exact `ReadResourceResult` shape. Final dispatch calls the final
    /// handler hook directly so embedded resource metadata, open fields, and
    /// cache hints are not projected through the legacy resource surface.
    async fn handle_resources_read_final_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: FinalReadResourceParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
        resume_inputs: Option<&MrtrCompletedInputs>,
    ) -> McpResult<FinalMethodOutcome<FinalReadResourceResult>> {
        let progress_marker = final_progress_marker(&params.meta)?;
        let uri = params.uri.as_str();
        debug!(
            target: targets::HANDLER,
            "reading final resource; resource_key={}",
            safe_log_label(uri)
        );

        let dispatch_started_at = request_ctx.cx().now();
        if request_cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        if !session_state.is_resource_enabled(uri) {
            return Err(McpError::new(
                McpErrorCode::ResourceNotFound,
                format!("Resource '{uri}' is disabled for this session"),
            ));
        }

        let resolved = self.resolve_resource(uri).ok_or_else(|| {
            McpError::with_data(
                McpErrorCode::InvalidParams,
                "Resource not found",
                serde_json::json!({"uri": uri}),
            )
        })?;
        if !resolved.final_enabled {
            return Err(McpError::invalid_params(
                "resource is registered only for exact MCP 2024-11-05 dispatch",
            ));
        }
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
            ProtocolEra::Modern2026,
        );
        let handler_timeout = read_handler_timeout(request_ctx.cx(), "resource_timeout", || {
            resolved.handler.timeout()
        })?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);
        let outcome =
            run_handler_in_request(&ctx, request_cx, effective_budget, "resource", |child_cx| {
                if let Some(resume_inputs) = resume_inputs {
                    resolved
                        .handler
                        .read_final_outcome_async_with_uri_resuming_in_request(
                            &ctx,
                            child_cx,
                            uri,
                            &resolved.params,
                            Some(resume_inputs),
                        )
                } else {
                    resolved
                        .handler
                        .read_final_outcome_async_with_uri_in_request(
                            &ctx,
                            child_cx,
                            uri,
                            &resolved.params,
                        )
                }
            })
            .await?;

        match outcome {
            Outcome::Ok(result) => Ok(result),
            Outcome::Err(error) => Err(sanitize_handler_error(request_ctx.cx(), "resource", error)),
            Outcome::Cancelled(_) => Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => {
                Err(sanitized_handler_panic(request_ctx.cx(), "resource"))
            }
        }
    }

    /// Handles the prompts/list request.
    ///
    /// If session_state is provided, disabled prompts will be filtered out.
    /// If include_tags/exclude_tags are provided, prompts are filtered by tags.
    pub fn handle_prompts_list(
        &self,
        request_ctx: &McpContext,
        params: ListPromptsParams,
        session_state: Option<&SessionState>,
    ) -> McpResult<ListPromptsResult> {
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        let tag_filters =
            TagFilters::new(params.include_tags.as_ref(), params.exclude_tags.as_ref());
        let tag_filters = if params.include_tags.is_some() || params.exclude_tags.is_some() {
            Some(&tag_filters)
        } else {
            None
        };
        let prompts =
            crate::catch_extension_unwind(|| self.prompts_filtered(session_state, tag_filters))
                .map_err(|_payload| {
                    sanitized_handler_panic(request_ctx.cx(), "prompt_definition")
                })?;
        let Some(page_size) = self.list_page_size else {
            return Ok(ListPromptsResult {
                prompts,
                next_cursor: None,
            });
        };

        let offset = decode_cursor_offset(params.cursor.as_deref())?;
        let end = offset.saturating_add(page_size).min(prompts.len());
        let next_cursor = if end < prompts.len() {
            Some(encode_cursor_offset(end))
        } else {
            None
        };
        Ok(ListPromptsResult {
            prompts: prompts.get(offset..end).unwrap_or_default().to_vec(),
            next_cursor,
        })
    }

    /// Handles the prompts/get request.
    ///
    /// # Arguments
    ///
    /// * `request_ctx` - Request authority for cancellation, identity, auth, and accounting
    /// * `params` - The prompt get parameters including name and arguments
    /// * `session_state` - Session state for per-session storage
    /// * `notification_sender` - Optional callback for sending progress notifications
    /// * `bidirectional_senders` - Optional senders for sampling/elicitation
    pub fn handle_prompts_get(
        &self,
        request_ctx: &McpContext,
        params: GetPromptParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<GetPromptResult> {
        debug!(
            target: targets::HANDLER,
            "getting prompt; prompt_key={}; arguments_present={}",
            safe_log_label(&params.name),
            params.arguments.is_some()
        );

        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }

        // Check if prompt is disabled for this session
        if !session_state.is_prompt_enabled(&params.name) {
            return Err(McpError::new(
                McpErrorCode::PromptNotFound,
                format!("Prompt '{}' is disabled for this session", params.name),
            ));
        }

        // Find the prompt handler
        let handler = self.prompts.get(&params.name).ok_or_else(|| {
            McpError::new(
                fastmcp_core::McpErrorCode::PromptNotFound,
                format!("Prompt not found: {}", params.name),
            )
        })?;
        if self.final_only_prompts.contains(&params.name) {
            return Err(McpError::new(
                fastmcp_core::McpErrorCode::PromptNotFound,
                format!("Prompt not found: {}", params.name),
            ));
        }
        let description = crate::catch_extension_unwind(|| handler.definition().description)
            .map_err(|_payload| sanitized_handler_panic(request_ctx.cx(), "prompt_definition"))?;

        // Extract progress marker from request metadata
        let progress_marker: Option<ProgressMarker> =
            params.meta.as_ref().and_then(|m| m.progress_marker.clone());

        // Clone the request authority so auth, budget accounting, cancellation,
        // and mask state remain shared with middleware and nested operations.
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
            ProtocolEra::Legacy2024,
        );

        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "prompt_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);

        // Get the prompt asynchronously - returns McpOutcome (4-valued)
        let arguments = params.arguments.unwrap_or_default();
        let outcome = run_handler(&ctx, effective_budget, "prompt", || {
            handler.get_async(&ctx, arguments)
        })?;

        // Convert 4-valued Outcome to McpResult for JSON-RPC response
        let messages = match outcome {
            Outcome::Ok(messages) => messages,
            Outcome::Err(error) => {
                return Err(sanitize_handler_error(request_ctx.cx(), "prompt", error));
            }
            Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => {
                return Err(sanitized_handler_panic(request_ctx.cx(), "prompt"));
            }
        };

        Ok(GetPromptResult {
            description,
            messages: legacy_prompt_messages_from_handler(messages)?,
            meta: None,
            additional: BTreeMap::new(),
        })
    }

    async fn handle_prompts_get_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: GetPromptParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
    ) -> McpResult<GetPromptResult> {
        debug!(
            target: targets::HANDLER,
            "getting modern prompt; prompt_key={}; arguments_present={}",
            safe_log_label(&params.name),
            params.arguments.is_some()
        );

        let dispatch_started_at = request_ctx.cx().now();
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        if !session_state.is_prompt_enabled(&params.name) {
            return Err(McpError::new(
                McpErrorCode::PromptNotFound,
                format!("Prompt '{}' is disabled for this session", params.name),
            ));
        }

        let handler = self.prompts.get(&params.name).ok_or_else(|| {
            McpError::new(
                McpErrorCode::PromptNotFound,
                format!("Prompt not found: {}", params.name),
            )
        })?;
        if self.final_only_prompts.contains(&params.name) {
            return Err(McpError::new(
                McpErrorCode::PromptNotFound,
                format!("Prompt not found: {}", params.name),
            ));
        }
        let description = crate::catch_extension_unwind(|| handler.definition().description)
            .map_err(|_payload| sanitized_handler_panic(request_ctx.cx(), "prompt_definition"))?;
        let progress_marker = params
            .meta
            .as_ref()
            .and_then(|meta| meta.progress_marker.clone());
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
            ProtocolEra::Legacy2024,
        );
        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "prompt_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);
        let arguments = params.arguments.unwrap_or_default();
        let outcome =
            run_handler_in_request(&ctx, request_cx, effective_budget, "prompt", |child_cx| {
                handler.get_async_in_request(&ctx, child_cx, arguments)
            })
            .await?;

        let messages = match outcome {
            Outcome::Ok(messages) => messages,
            Outcome::Err(error) => {
                return Err(sanitize_handler_error(request_ctx.cx(), "prompt", error));
            }
            Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => {
                return Err(sanitized_handler_panic(request_ctx.cx(), "prompt"));
            }
        };

        Ok(GetPromptResult {
            description,
            messages: legacy_prompt_messages_from_handler(messages)?,
            meta: None,
            additional: BTreeMap::new(),
        })
    }

    /// Handles one final MCP 2026-07-28 `prompts/get` request.
    ///
    /// Legacy dispatch remains on [`Self::handle_prompts_get`], including its
    /// exact `GetPromptResult` projection. Final dispatch calls the final
    /// handler hook directly so handler-authored final content and complete
    /// result metadata never pass through the legacy prompt surface.
    async fn handle_prompts_get_final_in_request(
        &self,
        request_ctx: &McpContext,
        request_cx: &Cx,
        params: FinalGetPromptParams,
        session_state: SessionState,
        notification_sender: Option<&NotificationSender>,
        bidirectional_senders: Option<&BidirectionalSenders>,
        resume_inputs: Option<&MrtrCompletedInputs>,
    ) -> McpResult<FinalMethodOutcome<FinalGetPromptResult>> {
        debug!(
            target: targets::HANDLER,
            "getting final prompt; prompt_key={}; arguments_present={}",
            safe_log_label(&params.name),
            !params.arguments.is_absent()
        );

        let dispatch_started_at = request_ctx.cx().now();
        if request_cx.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }
        if let Some(error) = budget_error(request_ctx) {
            return Err(error);
        }
        let progress_marker = final_progress_marker(&params.meta)?;
        if !session_state.is_prompt_enabled(&params.name) {
            return Err(McpError::new(
                McpErrorCode::PromptNotFound,
                format!("Prompt '{}' is disabled for this session", params.name),
            ));
        }

        let handler = self
            .prompts
            .get(&params.name)
            .ok_or_else(|| McpError::invalid_params(format!("Unknown prompt: {}", params.name)))?;
        let final_registration = self.final_prompts.get(&params.name).ok_or_else(|| {
            McpError::invalid_params("prompt is registered only for exact MCP 2024-11-05 dispatch")
        })?;
        if params.arguments.is_explicit_null() {
            return Err(McpError::invalid_params(
                "prompts/get arguments must not be null",
            ));
        }
        let arguments = params.arguments.into_value().unwrap_or_default();
        if final_registration
            .definition
            .arguments
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|argument| {
                argument.required == Some(true) && !arguments.contains_key(&argument.name)
            })
        {
            return Err(McpError::invalid_params("Missing required prompt argument"));
        }
        if arguments.keys().any(|name| {
            !final_registration
                .definition
                .arguments
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|argument| &argument.name == name)
        }) {
            return Err(McpError::invalid_params("Unknown prompt argument"));
        }
        let ctx = derive_handler_context(
            request_ctx,
            progress_marker,
            notification_sender,
            bidirectional_senders,
            ProtocolEra::Modern2026,
        );
        let handler_timeout =
            read_handler_timeout(request_ctx.cx(), "prompt_timeout", || handler.timeout())?;
        let effective_budget = compose_handler_budget(
            request_ctx.cx().budget(),
            request_ctx.budget(),
            handler_timeout,
            dispatch_started_at,
        );
        let ctx = ctx.with_operation_deadline(effective_budget.deadline);
        let arguments = arguments.into_iter().collect();
        let outcome =
            run_handler_in_request(&ctx, request_cx, effective_budget, "prompt", |child_cx| {
                if let Some(resume_inputs) = resume_inputs {
                    handler.get_final_outcome_async_resuming_in_request(
                        &ctx,
                        child_cx,
                        arguments,
                        Some(resume_inputs),
                    )
                } else {
                    handler.get_final_outcome_async_in_request(&ctx, child_cx, arguments)
                }
            })
            .await?;

        match outcome {
            Outcome::Ok(result) => Ok(result),
            Outcome::Err(error) => Err(sanitize_handler_error(request_ctx.cx(), "prompt", error)),
            Outcome::Cancelled(_) => Err(McpError::request_cancelled()),
            Outcome::Panicked(_payload) => Err(sanitized_handler_panic(request_ctx.cx(), "prompt")),
        }
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Mount/Composition Support
// ============================================================================

/// Result of a mount operation.
#[derive(Debug, Default)]
pub struct MountResult {
    /// Number of tools mounted.
    pub tools: usize,
    /// Number of resources mounted.
    pub resources: usize,
    /// Number of resource templates mounted.
    pub resource_templates: usize,
    /// Number of prompts mounted.
    pub prompts: usize,
    /// Any warnings generated during mounting (e.g., name conflicts).
    pub warnings: Vec<String>,
    /// Errors that caused the mount operation to be rejected.
    ///
    /// A rejected mount does not mutate the destination router.
    pub errors: Vec<String>,
}

impl MountResult {
    /// Returns true if any components were mounted.
    #[must_use]
    pub fn has_components(&self) -> bool {
        self.tools > 0 || self.resources > 0 || self.resource_templates > 0 || self.prompts > 0
    }

    /// Returns true if mounting was not rejected.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }

    fn merge(&mut self, other: Self) {
        self.tools += other.tools;
        self.resources += other.resources;
        self.resource_templates += other.resource_templates;
        self.prompts += other.prompts;
        self.warnings.extend(other.warnings);
        self.errors.extend(other.errors);
    }
}

#[derive(Clone, Copy)]
enum MountSelection {
    All,
    Tools,
    Resources,
    Prompts,
}

impl MountSelection {
    const fn includes_tools(self) -> bool {
        matches!(self, Self::All | Self::Tools)
    }

    const fn includes_resources(self) -> bool {
        matches!(self, Self::All | Self::Resources)
    }

    const fn includes_prompts(self) -> bool {
        matches!(self, Self::All | Self::Prompts)
    }
}

impl Router {
    /// Applies a prefix to a name or URI.
    fn apply_prefix(name: &str, prefix: Option<&str>) -> String {
        match prefix {
            Some(p) if !p.is_empty() => format!("{}/{}", p, name),
            _ => name.to_string(),
        }
    }

    /// Validates a prefix string.
    ///
    /// Prefixes must be alphanumeric plus underscores and hyphens,
    /// and cannot contain slashes.
    fn validate_prefix(prefix: &str) -> Result<(), String> {
        if prefix.is_empty() {
            return Ok(());
        }
        if prefix.contains('/') {
            return Err("Invalid mount prefix: slashes are not permitted".to_string());
        }
        // Allow alphanumeric, underscore, hyphen
        for ch in prefix.chars() {
            if !ch.is_alphanumeric() && ch != '_' && ch != '-' {
                return Err(
                    "Invalid mount prefix: invalid characters are not permitted".to_string()
                );
            }
        }
        Ok(())
    }

    fn mount_preflight(
        &self,
        other: &Self,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
        selection: MountSelection,
    ) -> MountResult {
        let mut result = MountResult::default();

        if let Some(prefix) = prefix {
            if let Err(error) = Self::validate_prefix(prefix) {
                // Keep the warning for callers of the original API while also
                // recording the rejection as a real failure.
                result.warnings.push(error.clone());
                result.errors.push(error);
                return result;
            }
        }

        if behavior != crate::DuplicateBehavior::Error {
            return result;
        }

        let mut conflicts = Vec::new();
        if selection.includes_tools() {
            for name in other.tools.keys() {
                let mounted_name = Self::apply_prefix(name, prefix);
                if self.tools.contains_key(&mounted_name) {
                    conflicts.push(("Tool", mounted_name));
                }
            }
        }
        if selection.includes_resources() {
            for uri in other.resources.keys() {
                let mounted_uri = Self::apply_prefix(uri, prefix);
                if self.resources.contains_key(&mounted_uri) {
                    conflicts.push(("Resource", mounted_uri));
                }
            }
            for uri_template in other.resource_templates.keys() {
                let mounted_uri_template = Self::apply_prefix(uri_template, prefix);
                if self.resource_templates.contains_key(&mounted_uri_template) {
                    conflicts.push(("Resource template", mounted_uri_template));
                }
            }
        }
        if selection.includes_prompts() {
            for name in other.prompts.keys() {
                let mounted_name = Self::apply_prefix(name, prefix);
                if self.prompts.contains_key(&mounted_name) {
                    conflicts.push(("Prompt", mounted_name));
                }
            }
        }

        conflicts.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(&b.1)));
        result
            .errors
            .extend(conflicts.into_iter().map(|(kind, key)| {
                format!(
                    "Mount rejected because {kind} already exists; component_key={}",
                    safe_log_label(&key)
                )
            }));
        result
    }

    fn should_mount_duplicate(
        behavior: crate::DuplicateBehavior,
        kind: &'static str,
        key: &str,
        result: &mut MountResult,
    ) -> bool {
        match behavior {
            crate::DuplicateBehavior::Error => {
                result.errors.push(format!(
                    "Mount rejected because {kind} already exists; component_key={}",
                    safe_log_label(key)
                ));
                false
            }
            crate::DuplicateBehavior::Warn => {
                result.warnings.push(format!(
                    "{kind} already exists, keeping original; component_key={}",
                    safe_log_label(key)
                ));
                false
            }
            crate::DuplicateBehavior::Replace => {
                result.warnings.push(format!(
                    "{kind} already exists, replacing original; component_key={}",
                    safe_log_label(key)
                ));
                true
            }
            crate::DuplicateBehavior::Ignore => false,
        }
    }

    /// Mounts all handlers from another router with an optional prefix.
    ///
    /// This consumes the source router and moves its handlers into this router.
    /// Names/URIs are prefixed with `prefix/` if a prefix is provided.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut main_router = Router::new();
    /// let db_router = Router::new();
    /// // ... add handlers to db_router ...
    ///
    /// main_router.mount(db_router, Some("db"));
    /// // Tool "query" becomes "db/query"
    /// ```
    pub fn mount(&mut self, other: Router, prefix: Option<&str>) -> MountResult {
        self.mount_with_behavior(other, prefix, crate::DuplicateBehavior::Replace)
    }

    /// Mounts all handlers using the specified duplicate behavior.
    ///
    /// Prefix validation happens before any destination mutation. With
    /// [`crate::DuplicateBehavior::Error`], every selected component is
    /// preflighted and any conflict rejects the entire mount atomically.
    pub fn mount_with_behavior(
        &mut self,
        other: Router,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        let preflight = self.mount_preflight(&other, prefix, behavior, MountSelection::All);
        if !preflight.is_success() {
            return preflight;
        }

        let mut result = preflight;

        let Router {
            tools,
            tool_order,
            resources,
            final_only_resources,
            final_resources,
            resource_order,
            prompts,
            final_only_prompts,
            final_prompts,
            prompt_order,
            resource_templates,
            resource_template_order,
            ..
        } = other;

        // Mount tools
        result.merge(self.mount_tools_from(tools, tool_order, prefix, behavior));

        // Mount resources
        result.merge(self.mount_resources_from(
            resources,
            final_only_resources,
            final_resources,
            resource_order,
            prefix,
            behavior,
        ));

        // Mount resource templates
        result.merge(self.mount_resource_templates_from(
            resource_templates,
            resource_template_order,
            prefix,
            behavior,
        ));

        // Mount prompts
        result.merge(self.mount_prompts_from(
            prompts,
            final_only_prompts,
            final_prompts,
            prompt_order,
            prefix,
            behavior,
        ));

        // Log mount result
        if result.has_components() {
            debug!(
                target: targets::HANDLER,
                "mounted {} tools, {} resources, {} templates, {} prompts; prefix_present={}; prefix_key={}",
                result.tools,
                result.resources,
                result.resource_templates,
                result.prompts,
                prefix.is_some(),
                safe_log_label(prefix.unwrap_or_default())
            );
        }

        result
    }

    /// Mounts only tools from a router.
    pub fn mount_tools(&mut self, other: Router, prefix: Option<&str>) -> MountResult {
        self.mount_tools_with_behavior(other, prefix, crate::DuplicateBehavior::Replace)
    }

    /// Mounts only tools using the specified duplicate behavior.
    pub fn mount_tools_with_behavior(
        &mut self,
        other: Router,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        let preflight = self.mount_preflight(&other, prefix, behavior, MountSelection::Tools);
        if !preflight.is_success() {
            return preflight;
        }
        self.mount_tools_from(other.tools, other.tool_order, prefix, behavior)
    }

    /// Internal: mount tools from a HashMap.
    fn mount_tools_from(
        &mut self,
        mut tools: HashMap<String, AdmittedToolRegistration>,
        tool_order: Vec<String>,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        let mut result = MountResult::default();

        for name in tool_order {
            let Some(entry) = tools.remove(&name) else {
                continue;
            };
            let mounted_name = Self::apply_prefix(&name, prefix);
            trace!(
                target: targets::HANDLER,
                "mounting tool; source_key={}; mounted_key={}",
                safe_log_label(&name),
                safe_log_label(&mounted_name)
            );

            // Check for conflicts
            let existed = self.tools.contains_key(&mounted_name);
            if existed
                && !Self::should_mount_duplicate(behavior, "Tool", &mounted_name, &mut result)
            {
                continue;
            }

            // Rewrite the immutable definition snapshot and wrap only the
            // dispatch target. Admitted schemas and final metadata move as one
            // entry and are never recomputed during mounting.
            let mounted = entry.with_mounted_name(mounted_name.clone());
            let needs_order_push = !existed && !self.tool_order.iter().any(|n| n == &mounted_name);
            self.tools.insert(mounted_name.clone(), mounted);
            if needs_order_push {
                self.tool_order.push(mounted_name);
            }
            result.tools += 1;
        }

        if !tools.is_empty() {
            // Defensive: older Routers or unusual construction could leave items untracked by
            // tool_order. Mount them deterministically to avoid HashMap iteration order leaks.
            let mut remaining: Vec<(String, AdmittedToolRegistration)> =
                tools.into_iter().collect();
            remaining.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, entry) in remaining {
                let mounted_name = Self::apply_prefix(&name, prefix);

                let existed = self.tools.contains_key(&mounted_name);
                if existed
                    && !Self::should_mount_duplicate(behavior, "Tool", &mounted_name, &mut result)
                {
                    continue;
                }

                let mounted = entry.with_mounted_name(mounted_name.clone());
                self.tools.insert(mounted_name.clone(), mounted);
                if !existed && !self.tool_order.iter().any(|n| n == &mounted_name) {
                    self.tool_order.push(mounted_name);
                }
                result.tools += 1;
            }
        }

        result
    }

    /// Mounts only resources from a router.
    pub fn mount_resources(&mut self, other: Router, prefix: Option<&str>) -> MountResult {
        self.mount_resources_with_behavior(other, prefix, crate::DuplicateBehavior::Replace)
    }

    /// Mounts resources and resource templates using the specified duplicate
    /// behavior.
    pub fn mount_resources_with_behavior(
        &mut self,
        other: Router,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        let preflight = self.mount_preflight(&other, prefix, behavior, MountSelection::Resources);
        if !preflight.is_success() {
            return preflight;
        }

        let Router {
            resources,
            final_only_resources,
            final_resources,
            resource_order,
            resource_templates,
            resource_template_order,
            ..
        } = other;
        let mut result = preflight;
        result.merge(self.mount_resources_from(
            resources,
            final_only_resources,
            final_resources,
            resource_order,
            prefix,
            behavior,
        ));
        let template_result = self.mount_resource_templates_from(
            resource_templates,
            resource_template_order,
            prefix,
            behavior,
        );
        result.merge(template_result);
        result
    }

    /// Internal: mount resources from a HashMap.
    fn mount_resources_from(
        &mut self,
        mut resources: HashMap<String, BoxedResourceHandler>,
        final_only_resources: HashSet<String>,
        mut final_resources: HashMap<String, AdmittedFinalResourceRegistration>,
        resource_order: Vec<String>,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        use crate::handler::MountedResourceHandler;

        let mut result = MountResult::default();

        for uri in resource_order {
            let Some(handler) = resources.remove(&uri) else {
                continue;
            };
            let mounted_uri = Self::apply_prefix(&uri, prefix);
            trace!(
                target: targets::HANDLER,
                "mounting resource; source_key={}; mounted_key={}",
                safe_log_label(&uri),
                safe_log_label(&mounted_uri)
            );

            // Check for conflicts
            let existed = self.resources.contains_key(&mounted_uri);
            if existed
                && !Self::should_mount_duplicate(behavior, "Resource", &mounted_uri, &mut result)
            {
                continue;
            }

            // Wrap with mounted URI and insert
            let mounted = MountedResourceHandler::new(handler, uri.clone(), mounted_uri.clone());
            let needs_order_push =
                !existed && !self.resource_order.iter().any(|u| u == &mounted_uri);
            self.resources
                .insert(mounted_uri.clone(), Box::new(mounted));
            if prefix.is_none() {
                if let Some(final_registration) = final_resources.remove(&uri) {
                    self.final_resources
                        .insert(mounted_uri.clone(), final_registration);
                } else {
                    self.final_resources.remove(&mounted_uri);
                }
            } else {
                // Prefixed resource URIs are intentionally legacy-only: the
                // mounting namespace is not an absolute final URI.
                self.final_resources.remove(&mounted_uri);
            }
            if prefix.is_none() && final_only_resources.contains(&uri) {
                self.final_only_resources.insert(mounted_uri.clone());
            } else {
                self.final_only_resources.remove(&mounted_uri);
            }
            if needs_order_push {
                self.resource_order.push(mounted_uri);
            }
            result.resources += 1;
        }

        if !resources.is_empty() {
            let mut remaining: Vec<(String, BoxedResourceHandler)> =
                resources.into_iter().collect();
            remaining.sort_by(|a, b| a.0.cmp(&b.0));
            for (uri, handler) in remaining {
                let mounted_uri = Self::apply_prefix(&uri, prefix);

                let existed = self.resources.contains_key(&mounted_uri);
                if existed
                    && !Self::should_mount_duplicate(
                        behavior,
                        "Resource",
                        &mounted_uri,
                        &mut result,
                    )
                {
                    continue;
                }

                let mounted =
                    MountedResourceHandler::new(handler, uri.clone(), mounted_uri.clone());
                self.resources
                    .insert(mounted_uri.clone(), Box::new(mounted));
                if prefix.is_none() {
                    if let Some(final_registration) = final_resources.remove(&uri) {
                        self.final_resources
                            .insert(mounted_uri.clone(), final_registration);
                    } else {
                        self.final_resources.remove(&mounted_uri);
                    }
                } else {
                    self.final_resources.remove(&mounted_uri);
                }
                if prefix.is_none() && final_only_resources.contains(&uri) {
                    self.final_only_resources.insert(mounted_uri.clone());
                } else {
                    self.final_only_resources.remove(&mounted_uri);
                }
                if !existed && !self.resource_order.iter().any(|u| u == &mounted_uri) {
                    self.resource_order.push(mounted_uri);
                }
                result.resources += 1;
            }
        }

        result
    }

    /// Internal: mount resource templates from a HashMap.
    fn mount_resource_templates_from(
        &mut self,
        mut templates: HashMap<String, ResourceTemplateEntry>,
        resource_template_order: Vec<String>,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        use crate::handler::MountedResourceHandler;

        let mut result = MountResult::default();

        for uri_template in resource_template_order {
            let Some(entry) = templates.remove(&uri_template) else {
                continue;
            };
            let mounted_uri_template = Self::apply_prefix(&uri_template, prefix);
            trace!(
                target: targets::HANDLER,
                "mounting resource template; source_key={}; mounted_key={}",
                safe_log_label(&uri_template),
                safe_log_label(&mounted_uri_template)
            );

            // Check for conflicts
            let existed = self.resource_templates.contains_key(&mounted_uri_template);
            if existed
                && !Self::should_mount_duplicate(
                    behavior,
                    "Resource template",
                    &mounted_uri_template,
                    &mut result,
                )
            {
                continue;
            }

            // Create new template with mounted URI
            let mut mounted_template = entry.template.clone();
            mounted_template.uri_template = mounted_uri_template.clone();

            // Wrap handler if present
            let mounted_handler = entry.handler.map(|h| {
                let wrapped: BoxedResourceHandler =
                    Box::new(MountedResourceHandler::with_template(
                        h,
                        uri_template.clone(),
                        mounted_uri_template.clone(),
                        mounted_template.clone(),
                    ));
                wrapped
            });

            // Create new entry with mounted template
            let (matcher, specificity) = match admit_resource_template(&mounted_uri_template) {
                Ok(admitted) => admitted,
                Err(error) => {
                    result.errors.push(format!(
                        "Mount rejected resource template; template_key={}; code={:?}",
                        safe_log_label(&mounted_uri_template),
                        error.code
                    ));
                    continue;
                }
            };
            let mounted_entry = ResourceTemplateEntry {
                matcher,
                specificity,
                template: mounted_template,
                handler: mounted_handler,
                final_definition: entry.final_definition.map(|mut definition| {
                    definition.uri_template = mounted_uri_template.clone();
                    definition
                }),
                legacy_enabled: entry.legacy_enabled,
            };

            let needs_order_push = !existed
                && !self
                    .resource_template_order
                    .iter()
                    .any(|t| t == &mounted_uri_template);
            self.resource_templates
                .insert(mounted_uri_template.clone(), mounted_entry);
            if needs_order_push {
                self.resource_template_order.push(mounted_uri_template);
            }
            result.resource_templates += 1;
        }

        if !templates.is_empty() {
            let mut remaining: Vec<(String, ResourceTemplateEntry)> =
                templates.into_iter().collect();
            remaining.sort_by(|a, b| a.0.cmp(&b.0));
            for (uri_template, entry) in remaining {
                let mounted_uri_template = Self::apply_prefix(&uri_template, prefix);

                let existed = self.resource_templates.contains_key(&mounted_uri_template);
                if existed
                    && !Self::should_mount_duplicate(
                        behavior,
                        "Resource template",
                        &mounted_uri_template,
                        &mut result,
                    )
                {
                    continue;
                }

                let mut mounted_template = entry.template.clone();
                mounted_template.uri_template = mounted_uri_template.clone();

                let mounted_handler = entry.handler.map(|h| {
                    let wrapped: BoxedResourceHandler =
                        Box::new(MountedResourceHandler::with_template(
                            h,
                            uri_template,
                            mounted_uri_template.clone(),
                            mounted_template.clone(),
                        ));
                    wrapped
                });

                let (matcher, specificity) = match admit_resource_template(&mounted_uri_template) {
                    Ok(admitted) => admitted,
                    Err(error) => {
                        result.errors.push(format!(
                            "Mount rejected resource template; template_key={}; code={:?}",
                            safe_log_label(&mounted_uri_template),
                            error.code
                        ));
                        continue;
                    }
                };
                let mounted_entry = ResourceTemplateEntry {
                    matcher,
                    specificity,
                    template: mounted_template,
                    handler: mounted_handler,
                    final_definition: entry.final_definition.map(|mut definition| {
                        definition.uri_template = mounted_uri_template.clone();
                        definition
                    }),
                    legacy_enabled: entry.legacy_enabled,
                };

                self.resource_templates
                    .insert(mounted_uri_template.clone(), mounted_entry);
                if !existed
                    && !self
                        .resource_template_order
                        .iter()
                        .any(|t| t == &mounted_uri_template)
                {
                    self.resource_template_order
                        .push(mounted_uri_template.clone());
                }
                result.resource_templates += 1;
            }
        }

        // Rebuild sorted keys if we added templates
        if result.resource_templates > 0 {
            self.rebuild_sorted_template_keys();
        }

        result
    }

    /// Mounts only prompts from a router.
    pub fn mount_prompts(&mut self, other: Router, prefix: Option<&str>) -> MountResult {
        self.mount_prompts_with_behavior(other, prefix, crate::DuplicateBehavior::Replace)
    }

    /// Mounts only prompts using the specified duplicate behavior.
    pub fn mount_prompts_with_behavior(
        &mut self,
        other: Router,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        let preflight = self.mount_preflight(&other, prefix, behavior, MountSelection::Prompts);
        if !preflight.is_success() {
            return preflight;
        }
        self.mount_prompts_from(
            other.prompts,
            other.final_only_prompts,
            other.final_prompts,
            other.prompt_order,
            prefix,
            behavior,
        )
    }

    /// Internal: mount prompts from a HashMap.
    fn mount_prompts_from(
        &mut self,
        mut prompts: HashMap<String, BoxedPromptHandler>,
        final_only_prompts: HashSet<String>,
        mut final_prompts: HashMap<String, AdmittedFinalPromptRegistration>,
        prompt_order: Vec<String>,
        prefix: Option<&str>,
        behavior: crate::DuplicateBehavior,
    ) -> MountResult {
        use crate::handler::MountedPromptHandler;

        let mut result = MountResult::default();

        for name in prompt_order {
            let Some(handler) = prompts.remove(&name) else {
                continue;
            };
            let mounted_name = Self::apply_prefix(&name, prefix);
            trace!(
                target: targets::HANDLER,
                "mounting prompt; source_key={}; mounted_key={}",
                safe_log_label(&name),
                safe_log_label(&mounted_name)
            );

            // Check for conflicts
            let existed = self.prompts.contains_key(&mounted_name);
            if existed
                && !Self::should_mount_duplicate(behavior, "Prompt", &mounted_name, &mut result)
            {
                continue;
            }

            // Wrap with mounted name and insert
            let mounted = MountedPromptHandler::new(handler, mounted_name.clone());
            let needs_order_push =
                !existed && !self.prompt_order.iter().any(|n| n == &mounted_name);
            self.prompts.insert(mounted_name.clone(), Box::new(mounted));
            match final_prompts.remove(&name) {
                Some(mut final_registration) => {
                    final_registration.definition.name.clone_from(&mounted_name);
                    self.final_prompts
                        .insert(mounted_name.clone(), final_registration);
                }
                None => {
                    self.final_prompts.remove(&mounted_name);
                }
            }
            if final_only_prompts.contains(&name) {
                self.final_only_prompts.insert(mounted_name.clone());
            } else {
                self.final_only_prompts.remove(&mounted_name);
            }
            if needs_order_push {
                self.prompt_order.push(mounted_name);
            }
            result.prompts += 1;
        }

        if !prompts.is_empty() {
            let mut remaining: Vec<(String, BoxedPromptHandler)> = prompts.into_iter().collect();
            remaining.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, handler) in remaining {
                let mounted_name = Self::apply_prefix(&name, prefix);

                let existed = self.prompts.contains_key(&mounted_name);
                if existed
                    && !Self::should_mount_duplicate(behavior, "Prompt", &mounted_name, &mut result)
                {
                    continue;
                }

                let mounted = MountedPromptHandler::new(handler, mounted_name.clone());
                self.prompts.insert(mounted_name.clone(), Box::new(mounted));
                match final_prompts.remove(&name) {
                    Some(mut final_registration) => {
                        final_registration.definition.name.clone_from(&mounted_name);
                        self.final_prompts
                            .insert(mounted_name.clone(), final_registration);
                    }
                    None => {
                        self.final_prompts.remove(&mounted_name);
                    }
                }
                if final_only_prompts.contains(&name) {
                    self.final_only_prompts.insert(mounted_name.clone());
                } else {
                    self.final_only_prompts.remove(&mounted_name);
                }
                if !existed && !self.prompt_order.iter().any(|n| n == &mounted_name) {
                    self.prompt_order.push(mounted_name);
                }
                result.prompts += 1;
            }
        }

        result
    }

    /// Consumes the router and returns its internal handlers.
    ///
    /// This is used internally for mounting operations.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        HashMap<String, BoxedToolHandler>,
        HashMap<String, BoxedResourceHandler>,
        HashMap<String, ResourceTemplateEntry>,
        HashMap<String, BoxedPromptHandler>,
    ) {
        let tools = self
            .tools
            .into_iter()
            .map(|(name, entry)| (name, entry.handler))
            .collect();
        (tools, self.resources, self.resource_templates, self.prompts)
    }
}

struct ResolvedResource<'a> {
    handler: &'a BoxedResourceHandler,
    params: UriParams,
    final_enabled: bool,
    legacy_enabled: bool,
}

/// Entry for a resource template with its matcher and optional handler.
pub(crate) struct ResourceTemplateEntry {
    pub(crate) matcher: ReversibleResourceTemplate,
    specificity: (usize, usize, usize),
    pub(crate) template: ResourceTemplate,
    pub(crate) handler: Option<BoxedResourceHandler>,
    final_definition: Option<FinalResourceTemplate>,
    legacy_enabled: bool,
}

/// Parses a resource template with the canonical RFC 6570 implementation and
/// admits only templates the protocol can reverse-match exactly for routing.
fn admit_resource_template(
    source: &str,
) -> McpResult<(ReversibleResourceTemplate, (usize, usize, usize))> {
    let template = fastmcp_protocol::UriTemplate::parse(source)
        .map_err(|_| McpError::invalid_params("resource template is not valid RFC 6570"))?;
    let specificity = resource_template_specificity(&template);
    let matcher = template
        .compile_reversible()
        .map_err(|_| McpError::invalid_params("resource template cannot be matched reversibly"))?;
    Ok((matcher, specificity))
}

fn resource_template_specificity(
    template: &fastmcp_protocol::UriTemplate,
) -> (usize, usize, usize) {
    let mut literal_bytes = 0usize;
    let mut literal_parts = 0usize;
    for part in template.parts() {
        if let fastmcp_protocol::UriTemplatePart::Literal(literal) = part {
            literal_bytes = literal_bytes.saturating_add(literal.len());
            literal_parts = literal_parts.saturating_add(1);
        }
    }
    (literal_bytes, literal_parts, template.parts().len())
}

// ============================================================================
// Resource Reader Implementation
// ============================================================================

use fastmcp_core::{
    MAX_RESOURCE_READ_DEPTH, ResourceContentItem, ResourceReadResult, ResourceReader,
};
use std::pin::Pin;

/// A wrapper that implements `ResourceReader` for a shared `Router`.
///
/// This allows handlers to read resources from within tool/resource/prompt
/// handlers, enabling cross-component access.
#[derive(Clone)]
enum RouterAccess {
    Shared(Arc<Router>),
    RequestScoped(Weak<Router>),
}

impl RouterAccess {
    fn upgrade(&self) -> McpResult<Arc<Router>> {
        match self {
            Self::Shared(router) => Ok(Arc::clone(router)),
            Self::RequestScoped(router) => router.upgrade().ok_or_else(|| {
                McpError::new(
                    McpErrorCode::RequestCancelled,
                    "Request router is no longer available",
                )
            }),
        }
    }
}

pub(crate) struct RouterResourceReader {
    /// Access to the router without extending a server request's lifetime.
    router: RouterAccess,
    /// Session state for handlers.
    session_state: SessionState,
}

impl RouterResourceReader {
    /// Creates a new resource reader with the given router and session state.
    #[must_use]
    pub(crate) fn new(router: Arc<Router>, session_state: SessionState) -> Self {
        Self {
            router: RouterAccess::Shared(router),
            session_state,
        }
    }

    pub(crate) fn request_scoped(router: Weak<Router>, session_state: SessionState) -> Self {
        Self {
            router: RouterAccess::RequestScoped(router),
            session_state,
        }
    }

    fn from_access(router: RouterAccess, session_state: SessionState) -> Self {
        Self {
            router,
            session_state,
        }
    }
}

impl ResourceReader for RouterResourceReader {
    fn read_resource<'a>(
        &'a self,
        parent_ctx: &'a McpContext,
        uri: &'a str,
        depth: u32,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = fastmcp_core::McpResult<ResourceReadResult>>
                + Send
                + 'a,
        >,
    > {
        // Check recursion depth
        if depth > MAX_RESOURCE_READ_DEPTH {
            return Box::pin(async move {
                Err(McpError::new(
                    McpErrorCode::InternalError,
                    format!(
                        "Maximum resource read depth ({}) exceeded",
                        MAX_RESOURCE_READ_DEPTH
                    ),
                ))
            });
        }

        // Clone what we need for the async block
        let parent_ctx = parent_ctx.clone();
        let uri = uri.to_string();
        let router_access = self.router.clone();
        let session_state = self.session_state.clone();

        Box::pin(async move {
            debug!(
                target: targets::HANDLER,
                "cross-component resource read; resource_key={}; depth={}; request={}",
                safe_log_label(&uri),
                depth,
                parent_ctx.request_id()
            );
            let router = router_access.upgrade()?;
            let operation_started_at = parent_ctx.cx().now();
            if let Some(error) = budget_error(&parent_ctx) {
                return Err(error);
            }
            if !session_state.is_resource_enabled(&uri) {
                return Err(McpError::new(
                    McpErrorCode::ResourceNotFound,
                    format!("Resource '{}' is disabled for this session", uri),
                ));
            }

            // Resolve the resource
            let resolved = router.resolve_resource(&uri).ok_or_else(|| {
                McpError::new(
                    McpErrorCode::ResourceNotFound,
                    format!("Resource not found: {}", uri),
                )
            })?;
            let handler_timeout =
                read_handler_timeout(parent_ctx.cx(), "resource_timeout", || {
                    resolved.handler.timeout()
                })?;
            let effective_budget = compose_handler_budget(
                parent_ctx.cx().budget(),
                parent_ctx.budget(),
                handler_timeout,
                operation_started_at,
            );

            // Derive the child from the parent request authority, preserving
            // auth, mask state, budget accounting, and request identity.
            let nested_router = router_access.clone();
            let nested_state = session_state.clone();
            let child_ctx = parent_ctx
                .clone()
                .with_operation_deadline(effective_budget.deadline)
                .with_resource_read_depth(depth)
                .with_tool_call_depth(depth)
                .with_tool_caller(Arc::new(RouterToolCaller::from_access(
                    nested_router.clone(),
                    nested_state.clone(),
                )))
                .with_resource_reader(Arc::new(RouterResourceReader::from_access(
                    nested_router,
                    nested_state,
                )));

            // Read the resource
            let outcome = run_handler(&child_ctx, effective_budget, "resource", || {
                resolved
                    .handler
                    .read_async_with_uri(&child_ctx, &uri, &resolved.params)
            })?;

            // Convert outcome to result
            let contents = match outcome {
                Outcome::Ok(contents) => contents,
                Outcome::Err(error) => {
                    return Err(sanitize_handler_error(parent_ctx.cx(), "resource", error));
                }
                Outcome::Cancelled(_) => return Err(McpError::request_cancelled()),
                Outcome::Panicked(_payload) => {
                    return Err(sanitized_handler_panic(parent_ctx.cx(), "resource"));
                }
            };

            // Convert protocol ResourceContent to core ResourceContentItem
            let items: Vec<ResourceContentItem> = contents
                .into_iter()
                .map(|c| ResourceContentItem {
                    uri: c.uri,
                    mime_type: c.mime_type,
                    text: c.text,
                    blob: c.blob,
                })
                .collect();

            Ok(ResourceReadResult::new(items))
        })
    }
}

// ============================================================================
// Tool Caller Implementation
// ============================================================================

use fastmcp_core::{MAX_TOOL_CALL_DEPTH, ToolCallResult, ToolCaller, ToolContentItem};

/// A wrapper that implements `ToolCaller` for a shared `Router`.
///
/// This allows handlers to call other tools from within tool/resource/prompt
/// handlers, enabling cross-component access.
pub(crate) struct RouterToolCaller {
    /// Access to the router without extending a server request's lifetime.
    router: RouterAccess,
    /// Session state for handlers.
    session_state: SessionState,
}

impl RouterToolCaller {
    /// Creates a new tool caller with the given router and session state.
    #[must_use]
    pub(crate) fn new(router: Arc<Router>, session_state: SessionState) -> Self {
        Self {
            router: RouterAccess::Shared(router),
            session_state,
        }
    }

    pub(crate) fn request_scoped(router: Weak<Router>, session_state: SessionState) -> Self {
        Self {
            router: RouterAccess::RequestScoped(router),
            session_state,
        }
    }

    fn from_access(router: RouterAccess, session_state: SessionState) -> Self {
        Self {
            router,
            session_state,
        }
    }
}

impl ToolCaller for RouterToolCaller {
    fn call_tool<'a>(
        &'a self,
        parent_ctx: &'a McpContext,
        name: &'a str,
        args: serde_json::Value,
        depth: u32,
    ) -> Pin<
        Box<dyn std::future::Future<Output = fastmcp_core::McpResult<ToolCallResult>> + Send + 'a>,
    > {
        // Check recursion depth
        if depth > MAX_TOOL_CALL_DEPTH {
            return Box::pin(async move {
                Err(McpError::new(
                    McpErrorCode::InternalError,
                    format!("Maximum tool call depth ({}) exceeded", MAX_TOOL_CALL_DEPTH),
                ))
            });
        }

        // Clone what we need for the async block
        let parent_ctx = parent_ctx.clone();
        let name = name.to_string();
        let router_access = self.router.clone();
        let session_state = self.session_state.clone();

        Box::pin(async move {
            debug!(
                target: targets::HANDLER,
                "cross-component tool call; tool_key={}; depth={}; request={}",
                safe_log_label(&name),
                depth,
                parent_ctx.request_id()
            );
            let router = router_access.upgrade()?;
            let operation_started_at = parent_ctx.cx().now();
            if let Some(error) = budget_error(&parent_ctx) {
                return Err(error);
            }
            if !session_state.is_tool_enabled(&name) {
                return Err(McpError::new(
                    McpErrorCode::MethodNotFound,
                    format!("Tool '{}' is disabled for this session", name),
                ));
            }

            // Find the tool handler
            let entry = router
                .tools
                .get(&name)
                .ok_or_else(|| McpError::method_not_found(&format!("tool: {}", name)))?;
            if !entry.legacy_enabled {
                return Err(McpError::method_not_found(&format!("tool: {}", name)));
            }
            let handler = &entry.handler;

            // Validate arguments against the tool's input schema
            // Use strict or lenient validation based on router configuration
            let validation_result = if router.strict_input_validation {
                validate_strict(&entry.definition.input_schema, &args)
            } else {
                validate(&entry.definition.input_schema, &args)
            };

            if let Err(validation_errors) = validation_result {
                let error_messages: Vec<String> = validation_errors
                    .iter()
                    .map(|e| format!("{}: {}", e.path, e.message))
                    .collect();
                return Err(McpError::invalid_params(format!(
                    "Input validation failed: {}",
                    error_messages.join("; ")
                )));
            }
            let handler_timeout =
                read_handler_timeout(parent_ctx.cx(), "tool_timeout", || handler.timeout())?;
            let effective_budget = compose_handler_budget(
                parent_ctx.cx().budget(),
                parent_ctx.budget(),
                handler_timeout,
                operation_started_at,
            );

            // Derive the child from the parent request authority, preserving
            // auth, mask state, budget accounting, and request identity.
            let nested_router = router_access.clone();
            let nested_state = session_state.clone();
            let child_ctx = parent_ctx
                .clone()
                .with_operation_deadline(effective_budget.deadline)
                .with_tool_call_depth(depth)
                .with_resource_read_depth(depth)
                .with_tool_caller(Arc::new(RouterToolCaller::from_access(
                    nested_router.clone(),
                    nested_state.clone(),
                )))
                .with_resource_reader(Arc::new(RouterResourceReader::from_access(
                    nested_router,
                    nested_state,
                )));

            // Call the tool
            let outcome = run_handler(&child_ctx, effective_budget, "tool", || {
                handler.call_async(&child_ctx, args)
            })?;

            // Convert outcome to result
            match outcome {
                Outcome::Ok(content) => {
                    // Convert protocol Content to core ToolContentItem
                    let items: Vec<ToolContentItem> = content
                        .into_iter()
                        .map(|c| match c {
                            Content::Text { text } => ToolContentItem::Text { text },
                            Content::Image { data, mime_type } => {
                                ToolContentItem::Image { data, mime_type }
                            }
                            Content::Audio { data, mime_type } => {
                                ToolContentItem::Audio { data, mime_type }
                            }
                            Content::Resource { resource } => ToolContentItem::Resource {
                                uri: resource.uri,
                                mime_type: resource.mime_type,
                                text: resource.text,
                                blob: resource.blob,
                            },
                        })
                        .collect();

                    Ok(ToolCallResult::success(items))
                }
                Outcome::Err(e) => {
                    let e = sanitize_handler_error(parent_ctx.cx(), "tool", e);
                    if is_framework_terminal_tool_error(e.code) {
                        return Err(e);
                    }
                    // Tool errors become error results, not failures
                    Ok(ToolCallResult::error(e.message))
                }
                Outcome::Cancelled(_) => Err(McpError::request_cancelled()),
                Outcome::Panicked(_payload) => {
                    Err(sanitized_handler_panic(parent_ctx.cx(), "tool"))
                }
            }
        })
    }
}

#[cfg(test)]
mod safe_log_label_tests {
    use super::{LOG_LABEL_HASH_INPUT_LIMIT, safe_log_label};

    #[test]
    fn safe_label_is_deterministic_non_verbatim_metadata() {
        let canary = "router-log-canary-secret";
        let first = format!("{}", safe_log_label(canary));
        let second = format!("{:?}", safe_log_label(canary));

        assert_eq!(first, second);
        assert!(first.contains(&format!("bytes={}", canary.len())));
        assert!(first.contains("sha256_prefix="));
        assert!(!first.contains(canary));
        assert_ne!(first, format!("{}", safe_log_label("different-label")));
    }

    #[test]
    fn safe_label_hashing_is_bounded_for_oversized_input() {
        let oversized = "x".repeat(LOG_LABEL_HASH_INPUT_LIMIT + 37);
        let rendered = format!("{}", safe_log_label(&oversized));

        assert!(rendered.contains(&format!("bytes={}", oversized.len())));
        assert!(rendered.contains(&format!("hashed_prefix_bytes={LOG_LABEL_HASH_INPUT_LIMIT}")));
        assert!(!rendered.contains(&oversized));
    }

    #[test]
    fn source_has_no_verbatim_argument_or_label_log_formats() {
        let source = include_str!("router.rs");
        let forbidden = [
            concat!("Tool ", "arguments:"),
            concat!("Prompt ", "arguments:"),
            concat!("Calling ", "tool: {}"),
            concat!("Reading ", "resource: {}"),
            concat!("Getting ", "prompt: {}"),
            concat!("Cross-component tool ", "call: {}"),
            concat!("Cross-component resource ", "read: {}"),
            concat!("Invalid URI template ", "'{}'"),
        ];

        for format in forbidden {
            assert!(!source.contains(format), "raw log format remains: {format}");
        }
    }
}

#[cfg(test)]
mod cursor_tests {
    use super::{decode_cursor_offset, encode_cursor_offset};

    #[test]
    fn roundtrip_zero() {
        let encoded = encode_cursor_offset(0);
        let decoded = decode_cursor_offset(Some(&encoded)).unwrap();
        assert_eq!(decoded, 0);
    }

    #[test]
    fn roundtrip_large_offset() {
        let encoded = encode_cursor_offset(12345);
        let decoded = decode_cursor_offset(Some(&encoded)).unwrap();
        assert_eq!(decoded, 12345);
    }

    #[test]
    fn none_cursor_returns_zero() {
        assert_eq!(decode_cursor_offset(None).unwrap(), 0);
    }

    #[test]
    fn invalid_base64_returns_error() {
        let err = decode_cursor_offset(Some("not-valid-base64!!!")).unwrap_err();
        assert!(err.message.contains("base64"));
    }

    #[test]
    fn valid_base64_but_not_json_returns_error() {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"not json");
        let err = decode_cursor_offset(Some(&encoded)).unwrap_err();
        assert!(err.message.contains("JSON"));
    }

    #[test]
    fn valid_json_but_no_offset_returns_error() {
        let payload = serde_json::json!({"other": 1});
        let bytes = serde_json::to_vec(&payload).unwrap();
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
        let err = decode_cursor_offset(Some(&encoded)).unwrap_err();
        assert!(err.message.contains("offset"));
    }
}

#[cfg(test)]
mod tag_filter_tests {
    use super::TagFilters;

    #[test]
    fn no_filters_matches_anything() {
        let f = TagFilters::default();
        assert!(f.matches(&[]));
        assert!(f.matches(&["a".to_string()]));
    }

    #[test]
    fn include_filter_requires_all_tags() {
        let include = vec!["a".to_string(), "b".to_string()];
        let f = TagFilters::new(Some(&include), None);
        assert!(f.matches(&["a".to_string(), "b".to_string(), "c".to_string()]));
        assert!(!f.matches(&["a".to_string()])); // missing "b"
    }

    #[test]
    fn exclude_filter_rejects_any_tag() {
        let exclude = vec!["x".to_string()];
        let f = TagFilters::new(None, Some(&exclude));
        assert!(f.matches(&["a".to_string(), "b".to_string()]));
        assert!(!f.matches(&["a".to_string(), "x".to_string()]));
    }

    #[test]
    fn include_and_exclude_combined() {
        let include = vec!["a".to_string()];
        let exclude = vec!["b".to_string()];
        let f = TagFilters::new(Some(&include), Some(&exclude));
        assert!(f.matches(&["a".to_string()]));
        assert!(!f.matches(&["a".to_string(), "b".to_string()])); // excluded
        assert!(!f.matches(&["c".to_string()])); // missing "a"
    }

    #[test]
    fn case_insensitive_matching() {
        let include = vec!["Alpha".to_string()];
        let f = TagFilters::new(Some(&include), None);
        assert!(f.matches(&["alpha".to_string()]));
        assert!(f.matches(&["ALPHA".to_string()]));
    }

    #[test]
    fn empty_include_array_passes_all() {
        let include: Vec<String> = vec![];
        let f = TagFilters::new(Some(&include), None);
        assert!(f.matches(&[]));
        assert!(f.matches(&["anything".to_string()]));
    }

    #[test]
    fn tag_filters_debug() {
        let f = TagFilters::default();
        let debug = format!("{:?}", f);
        assert!(debug.contains("TagFilters"));
    }
}

#[cfg(test)]
mod router_tests {
    use super::*;
    use crate::bidirectional::MrtrInputResponse;
    use crate::handler::{CompletionHandler, PromptHandler, ResourceHandler, ToolHandler};
    use crate::tasks::{
        ApplicationTaskSupervisor, FinalTaskSupervisorFuture, FinalTaskSupervisorHandoff,
        FinalTaskWorkDescriptor,
    };
    use crate::{FinalTaskRuntimeConfig, FinalTaskStore, InMemoryFinalTaskStore};
    use asupersync::channel::oneshot;
    use asupersync::runtime::{RuntimeBuilder, RuntimeHandle};
    use asupersync::types::CancelKind;
    use fastmcp_core::{McpContext, McpResult, SessionState};
    use fastmcp_protocol::common_types::{
        Annotations, ContentBlock, EmbeddedResourceContents, OpenMetadata, RawIcon,
    };
    use fastmcp_protocol::{
        CompleteResult, CompletionValues, Content, CoreResultDiscriminatorPolicy, DecodedResult,
        FinalCallToolResult, FinalCompletionParams, FinalGetPromptResult, FinalPromptMessage,
        LegacyCompletionParams, LegacyResourceContent, Prompt, PromptArgument, PromptMessage,
        Resource, ResourceContent, ResourceTemplate, ResultPeerEra, Tool, decode_peer_result,
    };
    use std::collections::BTreeMap;
    use std::fmt;
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::Poll;

    fn request_context(
        cx: &Cx,
        request_id: u64,
        budget: Budget,
        state: &SessionState,
    ) -> McpContext {
        McpContext::with_state(cx.clone(), request_id, state.clone()).with_budget_ceiling(budget)
    }

    async fn yield_once() {
        let mut yielded = false;
        std::future::poll_fn(|task_cx| {
            if std::mem::replace(&mut yielded, true) {
                Poll::Ready(())
            } else {
                task_cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
    }

    #[test]
    fn legacy_result_adapters_emit_exact_2024_defaults() {
        let tool = CallToolResult {
            content: legacy_contents_from_handler(vec![
                Content::Text {
                    text: "ready".to_owned(),
                },
                Content::Image {
                    data: "aGVsbG8=".to_owned(),
                    mime_type: "image/png".to_owned(),
                },
                Content::Resource {
                    resource: ResourceContent {
                        uri: "file:///tool.txt".to_owned(),
                        mime_type: Some("text/plain".to_owned()),
                        text: Some("tool resource".to_owned()),
                        blob: None,
                    },
                },
            ])
            .expect("handler content is representable by the exact legacy union"),
            is_error: false,
            meta: None,
            additional: BTreeMap::new(),
        };
        assert_eq!(
            serde_json::to_value(tool).expect("legacy tool result serializes"),
            serde_json::json!({
                "content": [
                    {"type": "text", "text": "ready"},
                    {"type": "image", "data": "aGVsbG8=", "mimeType": "image/png"},
                    {
                        "type": "resource",
                        "resource": {
                            "uri": "file:///tool.txt",
                            "mimeType": "text/plain",
                            "text": "tool resource"
                        }
                    }
                ]
            })
        );

        let resource = ReadResourceResult {
            contents: legacy_resource_contents_from_handler(vec![ResourceContent {
                uri: "file:///report.bin".to_owned(),
                mime_type: Some("application/octet-stream".to_owned()),
                text: None,
                blob: Some("AAEC".to_owned()),
            }])
            .expect("handler resource is representable by the exact legacy union"),
            meta: None,
            additional: BTreeMap::new(),
        };
        assert_eq!(
            serde_json::to_value(resource).expect("legacy resource result serializes"),
            serde_json::json!({
                "contents": [{
                    "uri": "file:///report.bin",
                    "mimeType": "application/octet-stream",
                    "blob": "AAEC"
                }]
            })
        );

        let prompt = GetPromptResult {
            description: Some("ask a question".to_owned()),
            messages: legacy_prompt_messages_from_handler(vec![PromptMessage {
                role: fastmcp_protocol::Role::User,
                content: Content::Text {
                    text: "summarize".to_owned(),
                },
            }])
            .expect("handler prompt message is representable by the exact legacy union"),
            meta: None,
            additional: BTreeMap::new(),
        };
        assert_eq!(
            serde_json::to_value(prompt).expect("legacy prompt result serializes"),
            serde_json::json!({
                "description": "ask a question",
                "messages": [{
                    "role": "user",
                    "content": {"type": "text", "text": "summarize"}
                }]
            })
        );
    }

    #[test]
    fn legacy_resource_adapter_preserves_open_members_when_promoted() {
        let resource = LegacyResourceContent::Text {
            uri: "file:///open.txt".to_owned(),
            text: "preserve me".to_owned(),
            mime_type: Some("text/plain".to_owned()),
            additional: BTreeMap::from([
                (
                    "_meta".to_owned(),
                    serde_json::json!({"legacy": "uninterpreted"}),
                ),
                (
                    "com.example/legacy".to_owned(),
                    serde_json::json!({"retained": true}),
                ),
            ]),
        };

        let promoted = promote_legacy_resource_content(resource)
            .expect("schema-valid legacy resource is promotable");
        assert_eq!(
            serde_json::to_value(promoted).expect("promoted resource serializes"),
            serde_json::json!({
                "uri": "file:///open.txt",
                "mimeType": "text/plain",
                "text": "preserve me",
                "_meta": {"legacy": "uninterpreted"},
                "com.example/legacy": {"retained": true}
            })
        );
    }

    #[test]
    fn legacy_content_adapter_rejects_only_audio_without_mutating_baseline() {
        let baseline = vec![Content::Image {
            data: "aGVsbG8=".to_owned(),
            mime_type: "image/png".to_owned(),
        }];
        let baseline_wire = serde_json::to_value(
            legacy_contents_from_handler(baseline.clone())
                .expect("baseline content is representable by the legacy adapter"),
        )
        .expect("baseline legacy content serializes");
        let planted = vec![Content::Audio {
            data: "aGVsbG8=".to_owned(),
            mime_type: "image/png".to_owned(),
        }];

        assert!(
            legacy_contents_from_handler(planted).is_err(),
            "changing only the content discriminator to audio rejects the legacy adapter"
        );
        assert_eq!(
            serde_json::to_value(
                legacy_contents_from_handler(baseline)
                    .expect("baseline remains representable after rejection"),
            )
            .expect("baseline legacy content remains serializable"),
            baseline_wire,
            "rejected legacy conversion cannot mutate the accepted baseline"
        );
    }

    fn spawn_owned_modern_request(
        runtime: &RuntimeHandle,
        router: Arc<Router>,
        request_context_id: u64,
        wire_id: &'static str,
        label: &'static str,
        control_sender: Option<oneshot::Sender<Cx>>,
    ) -> oneshot::Receiver<McpResult<serde_json::Value>> {
        let (response_sender, response_receiver) = oneshot::channel();
        runtime
            .try_spawn_with_cx(move |request_cx| {
                if let Some(control_sender) = control_sender {
                    control_sender
                        .send_blocking(request_cx.clone())
                        .expect("the cancellation controller remains available");
                }
                // Modern tools/call computes an MRTR exchange binding, which
                // requires a session cache partition on the request context.
                let request_ctx = McpContext::with_state(
                    request_cx,
                    request_context_id,
                    SessionState::new(),
                );
                let request = JsonRpcRequest::new(
                    "tools/call",
                    Some(serde_json::json!({
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                        "name": "concurrent-modern-tool",
                        "arguments": {"request": label},
                    })),
                    wire_id,
                );
                async move {
                    let result = router.dispatch_stateless_owned(request_ctx, request).await;
                    response_sender
                        .send_blocking(result)
                        .expect("the modern dispatch observer remains available");
                }
            })
            .expect("the runtime admits the request owner");
        response_receiver
    }

    // ── Stub handlers ──────────────────────────────────────────────────

    struct NamedTool {
        name: String,
        tags: Vec<String>,
    }

    impl NamedTool {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                tags: vec![],
            }
        }
        fn with_tags(name: &str, tags: Vec<String>) -> Self {
            Self {
                name: name.to_string(),
                tags,
            }
        }
    }

    impl ToolHandler for NamedTool {
        fn definition(&self) -> Tool {
            Tool {
                name: self.name.clone(),
                description: Some(format!("Tool {}", self.name)),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: self.tags.clone(),
                annotations: None,
            }
        }
        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text(format!("called {}", self.name))])
        }
    }

    struct RouterProgressTool;

    impl ToolHandler for RouterProgressTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "router-progress-tool".to_owned(),
                description: None,
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["total"],
                    "properties": {"total": {"type": "number"}},
                    "additionalProperties": false,
                }),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn call(&self, ctx: &McpContext, args: serde_json::Value) -> McpResult<Vec<Content>> {
            let total = args
                .get("total")
                .and_then(serde_json::Value::as_f64)
                .ok_or_else(|| McpError::invalid_params("router progress total is required"))?;
            ctx.report_progress_with_total(12_000.0, total, Some("router-final"));
            Ok(vec![Content::text("progress emitted")])
        }
    }

    struct DuplicateInvariantTool {
        label: &'static str,
        schema_property: &'static str,
        legacy_calls: Arc<AtomicUsize>,
        final_calls: Arc<AtomicUsize>,
    }

    impl ToolHandler for DuplicateInvariantTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "duplicate-invariant-tool".to_owned(),
                description: Some(self.label.to_owned()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        (self.schema_property): {"type": "boolean"}
                    },
                    "additionalProperties": false
                }),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![self.label.to_owned()],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            self.legacy_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![Content::text(self.label)])
        }

        fn call_final_outcome(
            &self,
            _ctx: &McpContext,
            _args: serde_json::Value,
        ) -> McpResult<FinalToolOutcome> {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            Ok(FinalToolOutcome::Complete(final_tool_complete_result(
                FinalCallToolResult {
                    content: vec![ContentBlock::text(self.label)],
                    is_error: false,
                    structured_content: None,
                },
            )))
        }
    }

    /// A normal-registration candidate whose final output-schema field is
    /// invalid. It is used to prove admission rejects without catalog change.
    struct InvalidFinalSchemaNamedTool {
        name: String,
        tags: Vec<String>,
    }

    impl InvalidFinalSchemaNamedTool {
        fn with_tags(name: &str, tags: Vec<String>) -> Self {
            Self {
                name: name.to_owned(),
                tags,
            }
        }
    }

    impl ToolHandler for InvalidFinalSchemaNamedTool {
        fn definition(&self) -> Tool {
            Tool {
                name: self.name.clone(),
                description: Some(format!("Invalid-schema tool {}", self.name)),
                input_schema: serde_json::json!({"type": "object"}),
                // The final field itself must be a JSON object. This scalar
                // schema document is deliberately invalid for local normal
                // registration.
                output_schema: Some(serde_json::json!(false)),
                icon: None,
                version: None,
                tags: self.tags.clone(),
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text(format!("called {}", self.name))])
        }
    }

    fn final_tools_list_request(
        cursor: Option<&str>,
        include_tags: Option<Vec<&str>>,
        exclude_tags: Option<Vec<&str>>,
        id: i64,
    ) -> JsonRpcRequest {
        let mut params = serde_json::Map::new();
        params.insert(
            "_meta".to_owned(),
            serde_json::json!({
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }),
        );
        if let Some(cursor) = cursor {
            params.insert("cursor".to_owned(), serde_json::json!(cursor));
        }
        if let Some(include_tags) = include_tags {
            params.insert("includeTags".to_owned(), serde_json::json!(include_tags));
        }
        if let Some(exclude_tags) = exclude_tags {
            params.insert("excludeTags".to_owned(), serde_json::json!(exclude_tags));
        }
        JsonRpcRequest::new("tools/list", Some(serde_json::Value::Object(params)), id)
    }

    fn mounted_tool_router() -> Router {
        let mut source = Router::new();
        source
            .add_tool(NamedTool::with_tags("first", vec!["visible".to_owned()]))
            .expect("tool registration succeeds");
        source
            .add_tool(NamedTool::with_tags("second", vec!["visible".to_owned()]))
            .expect("tool registration succeeds");
        source
            .add_tool(NamedTool::with_tags(
                "excluded",
                vec!["visible".to_owned(), "excluded".to_owned()],
            ))
            .expect("tool registration succeeds");
        source
            .add_tool(NamedTool::with_tags("other", vec!["other".to_owned()]))
            .expect("tool registration succeeds");

        let mut router = Router::new();
        let mounted = router.mount_tools(source, Some("peer"));
        assert_eq!(mounted.tools, 4);
        router
    }

    static MACRO_DUAL_ERA_TOOL_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn final_tool_complete_result(
        payload: FinalCallToolResult,
    ) -> CompleteResult<FinalCallToolResult> {
        let params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
            "name": "macro_dual_era_tool",
        });
        let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params))
            .expect("test final tools/call request");
        let mut wire = serde_json::to_value(payload).expect("final tool payload serializes");
        wire.as_object_mut()
            .expect("final tool payload is an object")
            .insert("resultType".to_owned(), serde_json::json!("complete"));
        let encoded = serde_json::to_string(&wire).expect("final tool wire serializes");
        let CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) = request
            .decode_result(&encoded)
            .expect("typed final tools/call result")
        else {
            panic!("typed final tools/call result is selected");
        };
        result
    }

    #[fastmcp_derive::tool]
    fn macro_dual_era_tool() -> CompleteResult<FinalCallToolResult> {
        MACRO_DUAL_ERA_TOOL_CALLS.fetch_add(1, Ordering::SeqCst);
        final_tool_complete_result(FinalCallToolResult {
            content: vec![ContentBlock::text("macro final tool result")],
            is_error: false,
            structured_content: Some(serde_json::json!({"weather":"clear"})),
        })
    }

    struct SchemaBoundaryTool {
        final_calls: Arc<AtomicUsize>,
        legacy_calls: Arc<AtomicUsize>,
        output_matches_schema: bool,
        output_is_error: bool,
        output_has_unevaluated_property: bool,
        invalid_final_input_schema: bool,
        missing_final_input_object_type: bool,
        invalid_final_output_schema: bool,
    }

    impl ToolHandler for SchemaBoundaryTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "schema-boundary-tool".to_owned(),
                description: None,
                input_schema: if self.invalid_final_input_schema {
                    serde_json::json!(42)
                } else if self.missing_final_input_object_type {
                    serde_json::json!({"properties": {"value": {"type": "string"}}})
                } else {
                    serde_json::json!({
                        "$schema": "https://json-schema.org/draft/2020-12/schema",
                        "type": "object",
                        "required": ["value"],
                        "properties": {"value": {"type": "string"}},
                        "unevaluatedProperties": false,
                    })
                },
                output_schema: Some(if self.invalid_final_output_schema {
                    serde_json::json!(42)
                } else {
                    serde_json::json!({
                        "$schema": "https://json-schema.org/draft/2020-12/schema",
                        "type": "object",
                        "properties": {
                            "accepted": {"type": "boolean"},
                            "error": {
                                "enum": ["input-validation", "handler"]
                            }
                        },
                        "anyOf": [
                            {"required": ["accepted"]},
                            {"required": ["error"]}
                        ],
                        "unevaluatedProperties": false,
                    })
                }),
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            self.legacy_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![Content::text("legacy schema-boundary result")])
        }

        fn final_tool_error_structured_content(
            &self,
            kind: ToolErrorKind,
        ) -> Option<serde_json::Value> {
            Some(match kind {
                ToolErrorKind::InputValidation => {
                    serde_json::json!({"error": "input-validation"})
                }
                ToolErrorKind::Handler => serde_json::json!({"error": "handler"}),
            })
        }

        fn call_final_outcome(
            &self,
            _ctx: &McpContext,
            _args: serde_json::Value,
        ) -> McpResult<FinalToolOutcome> {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            let structured_content = if !self.output_matches_schema {
                serde_json::json!({"accepted": "not-a-boolean"})
            } else if self.output_has_unevaluated_property {
                serde_json::json!({"accepted": true, "unexpected": true})
            } else {
                serde_json::json!({"accepted": true})
            };
            Ok(FinalToolOutcome::Complete(final_tool_complete_result(
                FinalCallToolResult {
                    content: vec![ContentBlock::text("final schema-boundary result")],
                    is_error: self.output_is_error,
                    structured_content: Some(structured_content),
                },
            )))
        }
    }

    /// A dual-era tool whose admitted output schema and handlers deliberately
    /// differ across registrations. It proves a successful replacement commits
    /// both the handler and final schema together.
    struct AdmittedSchemaReplacementTool {
        legacy_calls: Arc<AtomicUsize>,
        final_calls: Arc<AtomicUsize>,
        legacy_label: &'static str,
        output_schema: serde_json::Value,
        structured_content: Option<serde_json::Value>,
    }

    impl ToolHandler for AdmittedSchemaReplacementTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "admitted-schema-replacement-tool".to_owned(),
                description: Some(self.legacy_label.to_owned()),
                input_schema: serde_json::json!({
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "unevaluatedProperties": false,
                }),
                output_schema: Some(self.output_schema.clone()),
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            self.legacy_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![Content::text(self.legacy_label)])
        }

        fn final_tool_error_structured_content(
            &self,
            kind: ToolErrorKind,
        ) -> Option<serde_json::Value> {
            match self
                .output_schema
                .get("type")
                .and_then(serde_json::Value::as_str)
            {
                Some("string") => Some(serde_json::json!(match kind {
                    ToolErrorKind::InputValidation => "input-validation-error",
                    ToolErrorKind::Handler => "handler-error",
                })),
                Some("boolean") => Some(serde_json::json!(matches!(kind, ToolErrorKind::Handler))),
                Some("null") => Some(serde_json::Value::Null),
                Some("object") => Some(serde_json::json!({
                    "error": match kind {
                        ToolErrorKind::InputValidation => "input-validation",
                        ToolErrorKind::Handler => "handler",
                    }
                })),
                _ => None,
            }
        }

        fn call_final_outcome(
            &self,
            _ctx: &McpContext,
            _args: serde_json::Value,
        ) -> McpResult<FinalToolOutcome> {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            Ok(FinalToolOutcome::Complete(final_tool_complete_result(
                FinalCallToolResult {
                    content: vec![ContentBlock::text(self.legacy_label)],
                    is_error: false,
                    structured_content: self.structured_content.clone(),
                },
            )))
        }
    }

    #[derive(Clone, Copy)]
    enum ErrorMapperMode {
        Complete,
        MissingHandler,
        InvalidHandler,
        OversizedHandler,
    }

    struct ErrorMappedTool {
        mode: ErrorMapperMode,
        calls: Arc<AtomicUsize>,
    }

    impl ToolHandler for ErrorMappedTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "error-mapped-tool".to_owned(),
                description: None,
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["value"],
                    "properties": {"value": {"type": "string"}},
                    "additionalProperties": false
                }),
                output_schema: Some(serde_json::json!({
                    "type": "object",
                    "required": ["error"],
                    "properties": {"error": {"type": "string"}},
                    "additionalProperties": false
                })),
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn final_tool_error_structured_content(
            &self,
            kind: ToolErrorKind,
        ) -> Option<serde_json::Value> {
            match (self.mode, kind) {
                (ErrorMapperMode::MissingHandler, ToolErrorKind::Handler) => None,
                (ErrorMapperMode::InvalidHandler, ToolErrorKind::Handler) => {
                    Some(serde_json::json!({"error": 7}))
                }
                (ErrorMapperMode::OversizedHandler, ToolErrorKind::Handler) => Some(
                    serde_json::json!({"error": "x".repeat(MAX_FINAL_TOOL_ERROR_STRUCTURED_CONTENT_BYTES)}),
                ),
                (_, ToolErrorKind::InputValidation) => {
                    Some(serde_json::json!({"error": "input-validation"}))
                }
                (_, ToolErrorKind::Handler) => Some(serde_json::json!({"error": "handler"})),
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(McpError::new(
                McpErrorCode::ToolExecutionError,
                "mapped handler failure",
            ))
        }
    }

    fn final_tools_call_request(
        name: &str,
        arguments: serde_json::Value,
        id: i64,
    ) -> JsonRpcRequest {
        JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "name": name,
                "arguments": arguments,
            })),
            id,
        )
    }

    #[test]
    fn final_router_progress_uses_exact_numbers_and_rejects_one_smaller_total() {
        let mut router = Router::new();
        router
            .add_tool(RouterProgressTool)
            .expect("router progress tool registers for both eras");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 177, Budget::INFINITE, &state);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let notification_sender: NotificationSender = Arc::new(move |notification| {
            sent_clone
                .lock()
                .expect("notification collection is not poisoned")
                .push(notification);
        });
        let baseline = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "progressToken": "router-final-progress",
            },
            "name": "router-progress-tool",
            "arguments": {"total": 12000.0},
        });
        let mut planted = baseline.clone();
        planted["arguments"]["total"] = serde_json::json!(11999.0);
        assert_eq!(
            baseline["_meta"], planted["_meta"],
            "the progress total is the sole planted request dimension"
        );
        assert_eq!(baseline["name"], planted["name"]);

        let baseline: FinalCallToolParams =
            serde_json::from_value(baseline).expect("baseline final request is valid");
        let outcome = block_on(router.handle_tools_call_final_in_request(
            &request_ctx,
            request_ctx.cx(),
            baseline,
            state.clone(),
            Some(&notification_sender),
            None,
            None,
        ))
        .expect("ordinary final router dispatch completes");
        assert!(matches!(outcome, FinalToolOutcome::Complete(_)));
        let notification = sent
            .lock()
            .expect("notification collection is not poisoned")[0]
            .clone();
        let wire = serde_json::to_string(
            notification
                .params
                .as_ref()
                .expect("ordinary final progress has parameters"),
        )
        .expect("ordinary final progress parameters serialize");
        assert!(wire.contains("\"progress\":12000"));
        assert!(wire.contains("\"total\":12000"));

        let planted: FinalCallToolParams =
            serde_json::from_value(planted).expect("one-variable planted request is valid");
        let outcome = block_on(router.handle_tools_call_final_in_request(
            &request_ctx,
            request_ctx.cx(),
            planted,
            state,
            Some(&notification_sender),
            None,
            None,
        ))
        .expect("the handler result remains valid when only total is smaller");
        assert!(matches!(outcome, FinalToolOutcome::Complete(_)));
        assert_eq!(
            sent.lock()
                .expect("notification collection is not poisoned")
                .len(),
            1,
            "the one-variable progress violation emits no second final notification"
        );
    }

    struct TaskCapableRouterTool {
        final_calls: Arc<AtomicUsize>,
    }

    impl ToolHandler for TaskCapableRouterTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "task-capable-router-tool".to_owned(),
                description: None,
                input_schema: serde_json::json!({
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "unevaluatedProperties": false,
                }),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn declares_final_tasks(&self) -> bool {
            true
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text("legacy task-capable router result")])
        }

        fn call_final_outcome(
            &self,
            _ctx: &McpContext,
            _args: serde_json::Value,
        ) -> McpResult<FinalToolOutcome> {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            Ok(FinalToolOutcome::CreateTask {
                work_descriptor: FinalTaskWorkDescriptor::new(serde_json::json!({
                    "operation": "task-capable-router-tool"
                }))?,
                status_message: Some("router task created".to_owned()),
            })
        }
    }

    /// Simulates a handler that overrides the request-owned hook and bypasses
    /// the trait's ordinary declaration guard. The router must still prevent
    /// its undeclared task outcome from reaching task creation.
    struct UndeclaredTaskOutcomeRouterTool {
        final_calls: Arc<AtomicUsize>,
    }

    impl ToolHandler for UndeclaredTaskOutcomeRouterTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "undeclared-task-outcome-router-tool".to_owned(),
                description: None,
                input_schema: serde_json::json!({
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "unevaluatedProperties": false,
                }),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text("legacy undeclared-task outcome")])
        }

        fn call_final_outcome_async_in_request<'a>(
            &'a self,
            _ctx: &'a McpContext,
            _request_cx: &'a Cx,
            _args: serde_json::Value,
        ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            let work_descriptor = FinalTaskWorkDescriptor::new(serde_json::json!({
                "operation": "undeclared-task-outcome-router-tool"
            }));
            Box::pin(async move {
                match work_descriptor {
                    Ok(work_descriptor) => Outcome::Ok(FinalToolOutcome::CreateTask {
                        work_descriptor,
                        status_message: None,
                    }),
                    Err(error) => Outcome::Err(error),
                }
            })
        }
    }

    struct NoopFinalTaskSupervisor;

    impl ApplicationTaskSupervisor for NoopFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            _handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            Box::pin(async { Ok(()) })
        }
    }

    fn task_runtime_for_router(store: Arc<InMemoryFinalTaskStore>) -> FinalTaskRuntime {
        let store: Arc<dyn FinalTaskStore> = store;
        FinalTaskRuntime::new(
            store,
            FinalTaskRuntimeConfig::new(60_000, Some(5_000))
                .expect("a finite final Task policy is valid"),
            Arc::new(|_notification| {}),
        )
    }

    fn final_task_capable_tool_request(id: i64) -> JsonRpcRequest {
        JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {
                        "extensions": {
                            "io.modelcontextprotocol/tasks": {}
                        }
                    },
                },
                "name": "task-capable-router-tool",
                "arguments": {},
            })),
            id,
        )
    }

    struct FinalCatalogTool {
        metadata: OpenMetadata,
        icons: Vec<RawIcon>,
    }

    impl ToolHandler for FinalCatalogTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "final-catalog-tool".to_owned(),
                description: Some("final catalog description".to_owned()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: Some(serde_json::json!({"type": "object"})),
                icon: Some(fastmcp_protocol::Icon::new("https://legacy.test/icon.png")),
                version: Some("legacy-version".to_owned()),
                tags: vec!["legacy-tag".to_owned()],
                annotations: None,
            }
        }

        fn final_title(&self) -> Option<&str> {
            Some("Final Catalog Tool")
        }

        fn final_icons(&self) -> Option<&[RawIcon]> {
            Some(&self.icons)
        }

        fn final_metadata(&self) -> Option<&OpenMetadata> {
            Some(&self.metadata)
        }

        fn final_definition(&self) -> Option<FinalTool> {
            Some(FinalTool {
                name: "final-catalog-tool".to_owned(),
                title: Some("Exact Final Catalog Tool".to_owned()),
                description: Some("exact final catalog description".to_owned()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: Some(serde_json::json!({"type": "object"})),
                annotations: Some(FinalToolAnnotations {
                    title: Some("Exact annotation title".to_owned()),
                    destructive: Some(false),
                    idempotent: Some(true),
                    read_only: Some(true),
                    open_world_hint: Some(false),
                }),
                icons: Some(self.icons.clone()),
                meta: Some(self.metadata.clone()),
            })
        }

        fn final_tool_error_structured_content(
            &self,
            kind: ToolErrorKind,
        ) -> Option<serde_json::Value> {
            Some(serde_json::json!({
                "error": match kind {
                    ToolErrorKind::InputValidation => "input-validation",
                    ToolErrorKind::Handler => "handler",
                }
            }))
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text("legacy final catalog result")])
        }
    }

    struct FinalCatalogResource {
        metadata: OpenMetadata,
        icons: Vec<RawIcon>,
        annotations: Annotations,
    }

    impl ResourceHandler for FinalCatalogResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "file:///final-catalog-resource".to_owned(),
                name: "final-catalog-resource".to_owned(),
                description: Some("final resource description".to_owned()),
                mime_type: Some("text/plain".to_owned()),
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn final_title(&self) -> Option<&str> {
            Some("Final Catalog Resource")
        }

        fn final_icons(&self) -> Option<&[RawIcon]> {
            Some(&self.icons)
        }

        fn final_annotations(&self) -> Option<&Annotations> {
            Some(&self.annotations)
        }

        fn final_metadata(&self) -> Option<&OpenMetadata> {
            Some(&self.metadata)
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(Vec::new())
        }
    }

    struct FinalCatalogResourceTemplate {
        metadata: OpenMetadata,
        icons: Vec<RawIcon>,
        annotations: Annotations,
    }

    impl ResourceHandler for FinalCatalogResourceTemplate {
        fn definition(&self) -> Resource {
            Resource {
                uri: "template://placeholder".to_owned(),
                name: "final-catalog-template".to_owned(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn template(&self) -> Option<ResourceTemplate> {
            Some(ResourceTemplate {
                uri_template: "template://{id}".to_owned(),
                name: "final-catalog-template".to_owned(),
                description: Some("final template description".to_owned()),
                mime_type: Some("application/json".to_owned()),
                icon: None,
                version: None,
                tags: Vec::new(),
            })
        }

        fn final_template_title(&self) -> Option<&str> {
            Some("Final Catalog Template")
        }

        fn final_template_icons(&self) -> Option<&[RawIcon]> {
            Some(&self.icons)
        }

        fn final_template_annotations(&self) -> Option<&Annotations> {
            Some(&self.annotations)
        }

        fn final_template_metadata(&self) -> Option<&OpenMetadata> {
            Some(&self.metadata)
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(Vec::new())
        }
    }

    struct FinalCatalogPrompt {
        metadata: OpenMetadata,
        icons: Vec<RawIcon>,
    }

    impl PromptHandler for FinalCatalogPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "final-catalog-prompt".to_owned(),
                description: Some("final prompt description".to_owned()),
                arguments: vec![PromptArgument {
                    name: "optional-argument".to_owned(),
                    description: Some("must remain explicitly false".to_owned()),
                    required: false,
                }],
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn final_title(&self) -> Option<&str> {
            Some("Final Catalog Prompt")
        }

        fn final_icons(&self) -> Option<&[RawIcon]> {
            Some(&self.icons)
        }

        fn final_metadata(&self) -> Option<&OpenMetadata> {
            Some(&self.metadata)
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Ok(Vec::new())
        }
    }

    struct DirectFinalPrompt {
        final_calls: Arc<AtomicUsize>,
    }

    impl PromptHandler for DirectFinalPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "direct-final-prompt".to_owned(),
                description: Some("legacy prompt definition".to_owned()),
                arguments: vec![],
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Err(McpError::internal_error(
                "legacy prompt projection must not service a final request",
            ))
        }

        fn get_final(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<CompleteResult<FinalGetPromptResult>> {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            let content_meta = OpenMetadata::try_from_entries([(
                "com.example/direct-prompt".to_owned(),
                serde_json::json!({"source": "final-handler"}),
            )])
            .expect("direct prompt content metadata is valid");
            Ok(CompleteResult::new(
                FinalGetPromptResult {
                    description: Some("direct final prompt description".to_owned()),
                    messages: vec![FinalPromptMessage {
                        role: fastmcp_protocol::Role::Assistant,
                        content: ContentBlock::Audio {
                            data: "aGVsbG8=".to_owned(),
                            mime_type: "audio/mpeg".to_owned(),
                            annotations: None,
                            meta: Some(content_meta),
                            additional: BTreeMap::from([(
                                "com.example/direct-field".to_owned(),
                                serde_json::json!(true),
                            )]),
                        },
                    }],
                },
                empty_final_result_meta()?,
            ))
        }
    }

    struct PromptArgumentBoundary {
        final_calls: Arc<AtomicUsize>,
        legacy_calls: Arc<AtomicUsize>,
    }

    impl PromptHandler for PromptArgumentBoundary {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "prompt-argument-boundary".to_owned(),
                description: None,
                arguments: vec![PromptArgument {
                    name: "topic".to_owned(),
                    description: Some("required modern prompt topic".to_owned()),
                    required: true,
                }],
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            self.legacy_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![PromptMessage {
                role: fastmcp_protocol::Role::Assistant,
                content: Content::text("legacy prompt-argument-boundary result"),
            }])
        }

        fn get_final(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<CompleteResult<FinalGetPromptResult>> {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            Ok(CompleteResult::new(
                FinalGetPromptResult {
                    description: None,
                    messages: vec![FinalPromptMessage {
                        role: fastmcp_protocol::Role::Assistant,
                        content: ContentBlock::text("final prompt-argument-boundary result"),
                    }],
                },
                empty_final_result_meta()?,
            ))
        }
    }

    /// Deliberately changes its legacy definition after registration. Modern
    /// prompt validation must use the admission snapshot instead.
    struct MutablePromptDefinition {
        expose_admitted_argument: Arc<AtomicBool>,
        final_calls: Arc<AtomicUsize>,
    }

    impl PromptHandler for MutablePromptDefinition {
        fn definition(&self) -> Prompt {
            let argument = if self.expose_admitted_argument.load(Ordering::SeqCst) {
                PromptArgument {
                    name: "topic".to_owned(),
                    description: Some("admitted required argument".to_owned()),
                    required: true,
                }
            } else {
                PromptArgument {
                    name: "mutated".to_owned(),
                    description: Some("must not affect final validation".to_owned()),
                    required: false,
                }
            };
            Prompt {
                name: "mutable-prompt-definition".to_owned(),
                description: None,
                arguments: vec![argument],
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Ok(Vec::new())
        }

        fn get_final(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<CompleteResult<FinalGetPromptResult>> {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            Ok(CompleteResult::new(
                FinalGetPromptResult {
                    description: None,
                    messages: Vec::new(),
                },
                empty_final_result_meta()?,
            ))
        }
    }

    fn input_required_result(forged_request_state: &str) -> InputRequiredResult {
        let encoded = serde_json::json!({
            "resultType": "input_required",
            "inputRequests": {"roots": {"method": "roots/list"}},
            "requestState": forged_request_state,
        })
        .to_string();
        let (decoded, diagnostic) = decode_peer_result(
            &encoded,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect("test input-required result decodes");
        assert!(diagnostic.is_none());
        let DecodedResult::InputRequired(result) = decoded else {
            panic!("test result is input_required");
        };
        result
    }

    fn router_roots_response_wire() -> serde_json::Value {
        serde_json::to_value(
            MrtrInputResponse::roots(fastmcp_protocol::ListRootsResult::empty())
                .expect("roots response serializes"),
        )
        .expect("roots response converts to a wire value")
    }

    struct InputRequiredTool {
        legacy_calls: Arc<AtomicUsize>,
        final_calls: Arc<AtomicUsize>,
    }

    impl ToolHandler for InputRequiredTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "input-required-tool".to_owned(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            self.legacy_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![Content::text("legacy tool result")])
        }

        fn call_final_outcome(
            &self,
            _ctx: &McpContext,
            _args: serde_json::Value,
        ) -> McpResult<FinalToolOutcome> {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            Ok(FinalToolOutcome::InputRequired(input_required_result(
                "tool-retry-state",
            )))
        }

        fn call_final_outcome_async_resuming_in_request<'a>(
            &'a self,
            ctx: &'a McpContext,
            _request_cx: &'a Cx,
            arguments: serde_json::Value,
            resume_inputs: Option<&'a MrtrCompletedInputs>,
        ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
            Box::pin(async move {
                let Some(resume_inputs) = resume_inputs else {
                    return Outcome::Err(McpError::internal_error("MRTR resume inputs were lost"));
                };
                match resume_inputs.roots("roots") {
                    Ok(Some(_)) => match self.call_final_outcome(ctx, arguments) {
                        Ok(result) => Outcome::Ok(result),
                        Err(error) => Outcome::Err(error),
                    },
                    Ok(None) => Outcome::Err(McpError::internal_error("MRTR roots input was lost")),
                    Err(error) => Outcome::Err(error),
                }
            })
        }
    }

    struct TaskCapableInputRequiredTool {
        final_calls: Arc<AtomicUsize>,
    }

    impl ToolHandler for TaskCapableInputRequiredTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "task-capable-input-required-tool".to_owned(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: Vec::new(),
                annotations: None,
            }
        }

        fn declares_final_tasks(&self) -> bool {
            true
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text(
                "legacy task-capable input-required result",
            )])
        }

        fn call_final_outcome(
            &self,
            _ctx: &McpContext,
            _args: serde_json::Value,
        ) -> McpResult<FinalToolOutcome> {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            Ok(FinalToolOutcome::InputRequired(input_required_result(
                "task-capable-tool-retry-state",
            )))
        }
    }

    struct InputRequiredResource {
        legacy_calls: Arc<AtomicUsize>,
        final_calls: Arc<AtomicUsize>,
    }

    impl ResourceHandler for InputRequiredResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "file:///input-required-resource".to_owned(),
                name: "input-required-resource".to_owned(),
                description: None,
                mime_type: Some("text/plain".to_owned()),
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            self.legacy_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![ResourceContent {
                uri: "file:///input-required-resource".to_owned(),
                mime_type: Some("text/plain".to_owned()),
                text: Some("legacy resource result".to_owned()),
                blob: None,
            }])
        }

        fn read_final_outcome(
            &self,
            _ctx: &McpContext,
        ) -> McpResult<FinalMethodOutcome<FinalReadResourceResult>> {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            Ok(FinalMethodOutcome::InputRequired(input_required_result(
                "resource-retry-state",
            )))
        }

        fn read_final_outcome_async_with_uri_resuming_in_request<'a>(
            &'a self,
            ctx: &'a McpContext,
            _request_cx: &'a Cx,
            _uri: &'a str,
            _params: &'a UriParams,
            resume_inputs: Option<&'a MrtrCompletedInputs>,
        ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>> {
            Box::pin(async move {
                let Some(resume_inputs) = resume_inputs else {
                    return Outcome::Err(McpError::internal_error("MRTR resume inputs were lost"));
                };
                match resume_inputs.roots("roots") {
                    Ok(Some(_)) => match self.read_final_outcome(ctx) {
                        Ok(result) => Outcome::Ok(result),
                        Err(error) => Outcome::Err(error),
                    },
                    Ok(None) => Outcome::Err(McpError::internal_error("MRTR roots input was lost")),
                    Err(error) => Outcome::Err(error),
                }
            })
        }
    }

    struct InputRequiredPrompt {
        legacy_calls: Arc<AtomicUsize>,
        final_calls: Arc<AtomicUsize>,
    }

    impl PromptHandler for InputRequiredPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "input-required-prompt".to_owned(),
                description: None,
                arguments: Vec::new(),
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            self.legacy_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }

        fn get_final_outcome(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<FinalMethodOutcome<FinalGetPromptResult>> {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            Ok(FinalMethodOutcome::InputRequired(input_required_result(
                "prompt-retry-state",
            )))
        }

        fn get_final_outcome_async_resuming_in_request<'a>(
            &'a self,
            ctx: &'a McpContext,
            _request_cx: &'a Cx,
            arguments: std::collections::HashMap<String, String>,
            resume_inputs: Option<&'a MrtrCompletedInputs>,
        ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalGetPromptResult>>> {
            Box::pin(async move {
                let Some(resume_inputs) = resume_inputs else {
                    return Outcome::Err(McpError::internal_error("MRTR resume inputs were lost"));
                };
                match resume_inputs.roots("roots") {
                    Ok(Some(_)) => match self.get_final_outcome(ctx, arguments) {
                        Ok(result) => Outcome::Ok(result),
                        Err(error) => Outcome::Err(error),
                    },
                    Ok(None) => Outcome::Err(McpError::internal_error("MRTR roots input was lost")),
                    Err(error) => Outcome::Err(error),
                }
            })
        }
    }

    fn direct_final_prompt_request(id: i64) -> JsonRpcRequest {
        JsonRpcRequest::new(
            "prompts/get",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "name": "direct-final-prompt",
            })),
            id,
        )
    }

    fn final_prompt_get_request(
        name: &str,
        arguments: serde_json::Value,
        id: i64,
    ) -> JsonRpcRequest {
        JsonRpcRequest::new(
            "prompts/get",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "name": name,
                "arguments": arguments,
            })),
            id,
        )
    }

    struct DirectFinalResource {
        legacy_calls: Arc<AtomicUsize>,
        final_calls: Arc<AtomicUsize>,
    }

    impl ResourceHandler for DirectFinalResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "file:///direct-final-resource".to_owned(),
                name: "direct-final-resource".to_owned(),
                description: Some("legacy resource definition".to_owned()),
                mime_type: Some("text/plain".to_owned()),
                icon: None,
                version: None,
                tags: Vec::new(),
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            self.legacy_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![ResourceContent {
                uri: "file:///direct-final-resource".to_owned(),
                mime_type: Some("text/plain".to_owned()),
                text: Some("legacy resource result".to_owned()),
                blob: None,
            }])
        }

        fn read_final(
            &self,
            _ctx: &McpContext,
        ) -> McpResult<CompleteResult<FinalReadResourceResult>> {
            self.final_calls.fetch_add(1, Ordering::SeqCst);
            let content_meta = OpenMetadata::try_from_entries([(
                "com.example/direct-resource".to_owned(),
                serde_json::json!({"source": "final-handler"}),
            )])
            .expect("direct resource content metadata is valid");
            Ok(CompleteResult::new(
                FinalReadResourceResult {
                    contents: vec![EmbeddedResourceContents::Text {
                        uri: AbsoluteUri::parse("file:///direct-final-resource")
                            .expect("routed direct resource URI is valid"),
                        text: "direct final resource result".to_owned(),
                        mime_type: Some("text/markdown".to_owned()),
                        meta: Some(content_meta),
                        additional: BTreeMap::from([(
                            "com.example/direct-field".to_owned(),
                            serde_json::json!(true),
                        )]),
                    }],
                    ttl_ms: 321,
                    cache_scope: CacheScope::Public,
                },
                empty_final_result_meta()?,
            ))
        }
    }

    fn direct_final_resource_request(id: i64) -> JsonRpcRequest {
        JsonRpcRequest::new(
            "resources/read",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "uri": "file:///direct-final-resource",
            })),
            id,
        )
    }

    struct EchoCompletion;

    impl CompletionHandler for EchoCompletion {
        fn complete_legacy(
            &self,
            _ctx: &McpContext,
            params: LegacyCompletionParams,
        ) -> McpResult<CompletionValues> {
            Ok(CompletionValues {
                values: vec![format!("{}ging", params.argument.value)],
                total: Some(1),
                has_more: Some(false),
            })
        }

        fn complete_final(
            &self,
            _ctx: &McpContext,
            params: FinalCompletionParams,
        ) -> McpResult<fastmcp_protocol::FinalCompletionValues> {
            Ok(fastmcp_protocol::FinalCompletionValues {
                values: vec![format!("{}ging", params.argument.value)],
                total: Some(fastmcp_protocol::JsonInteger::from(1_i64)),
                has_more: Some(false),
            })
        }
    }

    struct ConcurrentModernTool {
        started: Arc<AtomicUsize>,
        completed: Arc<Mutex<Vec<String>>>,
    }

    impl ConcurrentModernTool {
        fn new(started: Arc<AtomicUsize>, completed: Arc<Mutex<Vec<String>>>) -> Self {
            Self { started, completed }
        }
    }

    impl ToolHandler for ConcurrentModernTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "concurrent-modern-tool".to_string(),
                description: Some("deterministic modern dispatch probe".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["request"],
                    "properties": {"request": {"type": "string"}},
                }),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Err(McpError::internal_error(
                "concurrent modern dispatch requires the async request hook",
            ))
        }

        // The modern stateless in-request path consults the disjoint final
        // outcome hook, not `call_async_in_request`; override the hook the
        // router actually dispatches through.
        fn call_final_outcome_async_in_request<'a>(
            &'a self,
            ctx: &'a McpContext,
            request_cx: &'a Cx,
            arguments: serde_json::Value,
        ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
            Box::pin(async move {
                let label = arguments
                    .get("request")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("missing")
                    .to_string();
                self.started.fetch_add(1, Ordering::SeqCst);

                while self.started.load(Ordering::SeqCst) < 2 {
                    if ctx.checkpoint().is_err() || request_cx.is_cancel_requested() {
                        return Outcome::Cancelled(asupersync::CancelReason::user(
                            "request cancelled before concurrent admission",
                        ));
                    }
                    yield_once().await;
                }

                if label == "cancelled" {
                    loop {
                        if ctx.checkpoint().is_err() || request_cx.is_cancel_requested() {
                            return Outcome::Cancelled(asupersync::CancelReason::user(
                                "request cancellation observed by child Cx",
                            ));
                        }
                        yield_once().await;
                    }
                }

                if ctx.checkpoint().is_err() || request_cx.is_cancel_requested() {
                    return Outcome::Cancelled(asupersync::CancelReason::user(
                        "request cancelled before completion",
                    ));
                }
                self.completed
                    .lock()
                    .expect("completion probe lock is not poisoned")
                    .push(label.clone());
                match crate::handler::promote_legacy_tool_content(vec![Content::text(label)]) {
                    Ok(result) => Outcome::Ok(FinalToolOutcome::Complete(result)),
                    Err(error) => Outcome::Err(error),
                }
            })
        }
    }

    struct ErrorTool {
        name: &'static str,
        code: McpErrorCode,
    }

    impl ToolHandler for ErrorTool {
        fn definition(&self) -> Tool {
            Tool {
                name: self.name.to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Err(McpError::new(self.code, "nested tool error"))
        }
    }

    struct AlternatingTool {
        calls: Arc<AtomicU64>,
    }

    impl ToolHandler for AlternatingTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "alternating_tool".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Err(McpError::internal_error("async alternating tool only"))
        }

        fn call_async<'a>(
            &'a self,
            ctx: &'a McpContext,
            _arguments: serde_json::Value,
        ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                match ctx.read_resource("loop://resource").await {
                    Ok(_) => Outcome::Ok(vec![Content::text("unexpected completion")]),
                    Err(error) => Outcome::Err(error),
                }
            })
        }
    }

    struct NamedResource {
        uri: String,
        tags: Vec<String>,
    }

    impl NamedResource {
        fn new(uri: &str) -> Self {
            Self {
                uri: uri.to_string(),
                tags: vec![],
            }
        }
        fn with_tags(uri: &str, tags: Vec<String>) -> Self {
            Self {
                uri: uri.to_string(),
                tags,
            }
        }
    }

    impl ResourceHandler for NamedResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: self.uri.clone(),
                name: self.uri.clone(),
                description: None,
                mime_type: Some("text/plain".to_string()),
                icon: None,
                version: None,
                tags: self.tags.clone(),
            }
        }
        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![ResourceContent {
                uri: self.uri.clone(),
                mime_type: Some("text/plain".to_string()),
                text: Some("content".to_string()),
                blob: None,
            }])
        }
    }

    struct AlternatingResource {
        calls: Arc<AtomicU64>,
    }

    impl ResourceHandler for AlternatingResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "loop://resource".to_string(),
                name: "alternating-resource".to_string(),
                description: None,
                mime_type: Some("text/plain".to_string()),
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Err(McpError::internal_error("async alternating resource only"))
        }

        fn read_async<'a>(
            &'a self,
            ctx: &'a McpContext,
        ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                match ctx
                    .call_tool("alternating_tool", serde_json::json!({}))
                    .await
                {
                    Ok(_) => Outcome::Ok(vec![ResourceContent {
                        uri: "loop://resource".to_string(),
                        mime_type: Some("text/plain".to_string()),
                        text: Some("unexpected completion".to_string()),
                        blob: None,
                    }]),
                    Err(error) => Outcome::Err(error),
                }
            })
        }
    }

    struct CostLedgerTool {
        remaining_after_parent_debit: Arc<AtomicU64>,
        remaining_after_nested_read: Arc<AtomicU64>,
    }

    impl ToolHandler for CostLedgerTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "cost_ledger_tool".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Err(McpError::internal_error("async cost-ledger tool only"))
        }

        fn call_async<'a>(
            &'a self,
            ctx: &'a McpContext,
            _arguments: serde_json::Value,
        ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
            Box::pin(async move {
                if ctx.consume_cost(1).is_err() {
                    return Outcome::Err(McpError::request_cancelled());
                }
                self.remaining_after_parent_debit.store(
                    ctx.budget()
                        .cost_quota
                        .expect("test request has finite cost quota"),
                    Ordering::Relaxed,
                );

                if let Err(error) = ctx.read_resource("cost://nested").await {
                    return Outcome::Err(error);
                }
                self.remaining_after_nested_read.store(
                    ctx.budget()
                        .cost_quota
                        .expect("test request has finite cost quota"),
                    Ordering::Relaxed,
                );
                Outcome::Ok(vec![Content::text("shared ledger")])
            })
        }
    }

    struct CostLedgerResource {
        remaining_after_nested_debit: Arc<AtomicU64>,
    }

    impl ResourceHandler for CostLedgerResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "cost://nested".to_string(),
                name: "cost-ledger-resource".to_string(),
                description: None,
                mime_type: Some("text/plain".to_string()),
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            ctx.consume_cost(1)
                .map_err(|_| McpError::request_cancelled())?;
            self.remaining_after_nested_debit.store(
                ctx.budget()
                    .cost_quota
                    .expect("test request has finite cost quota"),
                Ordering::Relaxed,
            );
            Ok(vec![ResourceContent {
                uri: "cost://nested".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("nested debit".to_string()),
                blob: None,
            }])
        }
    }

    struct NamedPrompt {
        name: String,
        tags: Vec<String>,
    }

    impl NamedPrompt {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                tags: vec![],
            }
        }
        fn with_tags(name: &str, tags: Vec<String>) -> Self {
            Self {
                name: name.to_string(),
                tags,
            }
        }
    }

    impl PromptHandler for NamedPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: self.name.clone(),
                description: Some(format!("Prompt {}", self.name)),
                arguments: vec![],
                icon: None,
                version: None,
                tags: self.tags.clone(),
            }
        }
        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Ok(vec![])
        }
    }

    fn marked_template(uri_template: &str, marker: &str) -> ResourceTemplate {
        ResourceTemplate {
            uri_template: uri_template.to_string(),
            name: marker.to_string(),
            description: Some(marker.to_string()),
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![marker.to_string()],
        }
    }

    fn marked_router(marker: &str) -> Router {
        let mut router = Router::new();
        router
            .add_tool(NamedTool::with_tags(
                "duplicate_tool",
                vec![marker.to_string()],
            ))
            .expect("tool registration succeeds");
        router.add_resource(NamedResource::with_tags(
            "duplicate://resource",
            vec![marker.to_string()],
        ));
        router.add_resource_template(marked_template("duplicate://{item}", marker));
        router.add_prompt(NamedPrompt::with_tags(
            "duplicate_prompt",
            vec![marker.to_string()],
        ));
        router
    }

    fn assert_router_marker(router: &Router, marker: &str) {
        assert_eq!(
            router
                .get_tool("duplicate_tool")
                .expect("tool exists")
                .definition()
                .tags,
            vec![marker.to_string()]
        );
        assert_eq!(
            router
                .get_resource("duplicate://resource")
                .expect("resource exists")
                .definition()
                .tags,
            vec![marker.to_string()]
        );
        assert_eq!(
            router
                .get_resource_template("duplicate://{item}")
                .expect("resource template exists")
                .tags,
            vec![marker.to_string()]
        );
        assert_eq!(
            router
                .get_prompt("duplicate_prompt")
                .expect("prompt exists")
                .definition()
                .tags,
            vec![marker.to_string()]
        );
    }

    struct BudgetProbeTool {
        timeout: Option<Duration>,
        delay: Duration,
        observed_deadline: Arc<Mutex<Option<Time>>>,
        timeout_read: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ToolHandler for BudgetProbeTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "budget_probe".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn timeout(&self) -> Option<Duration> {
            self.timeout_read.store(true, Ordering::Relaxed);
            self.timeout
        }

        fn call(&self, ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            *self
                .observed_deadline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = ctx.budget().deadline;
            if !self.delay.is_zero() {
                std::thread::sleep(self.delay);
            }
            Ok(vec![Content::text("completed")])
        }
    }

    struct SlowDefinitionTool {
        definition_reads: Arc<AtomicU64>,
        called: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ToolHandler for SlowDefinitionTool {
        fn definition(&self) -> Tool {
            if self.definition_reads.fetch_add(1, Ordering::Relaxed) > 0 {
                std::thread::sleep(Duration::from_millis(15));
            }
            Tool {
                name: "slow_definition".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn timeout(&self) -> Option<Duration> {
            Some(Duration::from_millis(1))
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            self.called.store(true, Ordering::Relaxed);
            Ok(vec![Content::text("must not run")])
        }
    }

    const PANIC_CANARY: &str = "Bearer peer-secret\n\u{001b}[31mred\u{001b}[0m\u{001b}]8;;https://invalid\u{0007}link\u{202e}";

    struct PanickingDisplay(String);

    impl fmt::Display for PanickingDisplay {
        fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("display-must-not-run: {}", self.0);
        }
    }

    struct UnwindingPanicTool {
        payload: String,
        non_string: bool,
    }

    impl ToolHandler for UnwindingPanicTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "panic_tool".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            unreachable!("the async override is the handler boundary under test")
        }

        fn call_async<'a>(
            &'a self,
            _ctx: &'a McpContext,
            _arguments: serde_json::Value,
        ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
            Box::pin(async move {
                if self.non_string {
                    std::panic::panic_any(PanickingDisplay(self.payload.clone()));
                }
                panic!("{}", self.payload);
            })
        }
    }

    struct OutcomePanicTool(String);

    impl ToolHandler for OutcomePanicTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "outcome_panic_tool".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            unreachable!("the async override is the handler boundary under test")
        }

        fn call_async<'a>(
            &'a self,
            _ctx: &'a McpContext,
            _arguments: serde_json::Value,
        ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
            Box::pin(async move {
                Outcome::Panicked(asupersync::types::PanicPayload::new(self.0.clone()))
            })
        }
    }

    struct OpaqueInternalTool;

    impl ToolHandler for OpaqueInternalTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "opaque_internal_tool".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Err(McpError::with_data(
                McpErrorCode::InternalError,
                PANIC_CANARY,
                serde_json::json!({"secret": PANIC_CANARY}),
            ))
        }
    }

    struct OpaqueInternalResource;

    impl ResourceHandler for OpaqueInternalResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "opaque://internal".to_string(),
                name: "opaque-internal-resource".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Err(McpError::with_data(
                McpErrorCode::InternalError,
                PANIC_CANARY,
                serde_json::json!({"secret": PANIC_CANARY}),
            ))
        }
    }

    struct OpaqueInternalPrompt;

    impl PromptHandler for OpaqueInternalPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "opaque_internal_prompt".to_string(),
                description: None,
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Err(McpError::with_data(
                McpErrorCode::InternalError,
                PANIC_CANARY,
                serde_json::json!({"secret": PANIC_CANARY}),
            ))
        }
    }

    struct PanicResource;

    impl ResourceHandler for PanicResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "panic://resource".to_string(),
                name: "panic-resource".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            panic!("{PANIC_CANARY}")
        }
    }

    struct PanicPrompt;

    impl PromptHandler for PanicPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "panic_prompt".to_string(),
                description: None,
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            panic!("{PANIC_CANARY}")
        }
    }

    struct DefinitionPanicTool(std::sync::atomic::AtomicBool);

    impl ToolHandler for DefinitionPanicTool {
        fn definition(&self) -> Tool {
            if self.0.swap(true, Ordering::Relaxed) {
                panic!("{PANIC_CANARY}");
            }
            Tool {
                name: "definition_panic_tool".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![])
        }
    }

    struct DefinitionPanicResource(std::sync::atomic::AtomicBool);

    impl ResourceHandler for DefinitionPanicResource {
        fn definition(&self) -> Resource {
            if self.0.swap(true, Ordering::Relaxed) {
                panic!("{PANIC_CANARY}");
            }
            Resource {
                uri: "panic://definition".to_string(),
                name: "definition-panic-resource".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![])
        }
    }

    struct TemplatePanicResource(std::sync::atomic::AtomicBool);

    impl ResourceHandler for TemplatePanicResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "panic-template://placeholder".to_string(),
                name: "template-panic-resource".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn template(&self) -> Option<ResourceTemplate> {
            if self.0.swap(true, Ordering::Relaxed) {
                panic!("{PANIC_CANARY}");
            }
            Some(ResourceTemplate {
                uri_template: "panic-template://{id}".to_string(),
                name: "template-panic-resource".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            })
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            unreachable!("templated reads use read_with_uri")
        }

        fn read_with_uri(
            &self,
            _ctx: &McpContext,
            uri: &str,
            _params: &UriParams,
        ) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: None,
                text: Some("template-content".to_string()),
                blob: None,
            }])
        }
    }

    struct DefinitionPanicPrompt(std::sync::atomic::AtomicBool);

    impl PromptHandler for DefinitionPanicPrompt {
        fn definition(&self) -> Prompt {
            if self.0.swap(true, Ordering::Relaxed) {
                panic!("{PANIC_CANARY}");
            }
            Prompt {
                name: "definition_panic_prompt".to_string(),
                description: None,
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: std::collections::HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Ok(vec![])
        }
    }

    // ── Router::new ────────────────────────────────────────────────────

    #[test]
    fn new_router_is_empty() {
        let r = Router::new();
        assert_eq!(r.tools_count(), 0);
        assert_eq!(r.resources_count(), 0);
        assert_eq!(r.resource_templates_count(), 0);
        assert_eq!(r.prompts_count(), 0);
        assert!(r.tools().is_empty());
        assert!(r.resources().is_empty());
        assert!(r.resource_templates().is_empty());
        assert!(r.prompts().is_empty());
    }

    #[test]
    fn default_router_is_empty() {
        let r = Router::default();
        assert_eq!(r.tools_count(), 0);
    }

    // ── add_tool / get_tool ────────────────────────────────────────────

    #[test]
    fn add_and_get_tool() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("my_tool"))
            .expect("tool registration succeeds");
        assert_eq!(r.tools_count(), 1);
        assert!(r.get_tool("my_tool").is_some());
        assert!(r.get_tool("other").is_none());
    }

    #[test]
    fn add_tool_replace_on_duplicate() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("t"))
            .expect("initial registration succeeds");
        r.add_tool(NamedTool::new("t"))
            .expect("valid replacement succeeds");
        assert_eq!(r.tools_count(), 1);
        // Order preserved (only one entry)
        assert_eq!(r.tools().len(), 1);
    }

    #[test]
    fn tools_returns_definitions_in_order() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("b"))
            .expect("tool registration succeeds");
        r.add_tool(NamedTool::new("a"))
            .expect("tool registration succeeds");
        let names: Vec<_> = r.tools().iter().map(|t| t.name.clone()).collect();
        assert_eq!(names, vec!["b", "a"]); // insertion order
    }

    #[test]
    fn explicit_legacy_tool_is_callable_only_on_exact_2024_routes() {
        let mut router = Router::new();
        router
            .add_legacy_tool(InvalidFinalSchemaNamedTool::with_tags(
                "legacy-only-tool",
                vec!["legacy".to_owned()],
            ))
            .expect("explicit legacy registration does not claim final admission");
        assert_eq!(
            router
                .tools()
                .into_iter()
                .map(|tool| tool.name)
                .collect::<Vec<_>>(),
            vec!["legacy-only-tool"]
        );
        assert!(
            !router
                .server_discovery_behavior_registry()
                .contains(ServerBehavior::ToolsList),
            "a legacy-only catalog cannot produce a modern discovery claim"
        );

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 78, Budget::INFINITE, &state);
        let legacy = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "legacy-only-tool".to_owned(),
                    arguments: Some(serde_json::json!({})),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("exact 2024 dispatch reaches the explicit legacy handler");
        assert_eq!(
            serde_json::to_value(legacy).expect("legacy result serializes")["content"][0]["text"],
            "called legacy-only-tool"
        );

        let modern_catalog = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_list_request(None, None, None, 79_i64),
            )
            .expect("modern tools/list remains a valid empty catalog");
        assert_eq!(modern_catalog["tools"], serde_json::json!([]));
        let modern_error = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request("legacy-only-tool", serde_json::json!({}), 80_i64),
            )
            .expect_err("modern dispatch cannot resolve an explicit legacy-only tool");
        assert_eq!(modern_error.code, McpErrorCode::InvalidParams);
        assert_eq!(router.tools_count(), 1);
    }

    #[test]
    fn explicit_legacy_resource_and_prompt_are_inert_on_final_routes() {
        let mut router = Router::new();
        router.add_legacy_resource(NamedResource::new("file:///legacy-only"));
        router.add_legacy_resource_template(marked_template("file:///{name}", "legacy-only"));
        router.add_legacy_prompt(NamedPrompt::new("legacy-only-prompt"));
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 181, Budget::INFINITE, &state);

        let legacy_resource = router
            .handle_resources_read(
                &request_ctx,
                &ReadResourceParams {
                    uri: "file:///legacy-only".to_owned(),
                    meta: None,
                },
                state.clone(),
                None,
                None,
            )
            .expect("the exact legacy resource route retains its explicit registration");
        assert_eq!(legacy_resource.contents.len(), 1);
        let legacy_prompt = router
            .handle_prompts_get(
                &request_ctx,
                GetPromptParams {
                    name: "legacy-only-prompt".to_owned(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("the exact legacy prompt route retains its explicit registration");
        assert!(legacy_prompt.messages.is_empty());

        let modern_resources = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    "resources/list",
                    Some(serde_json::json!({
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                    })),
                    182_i64,
                ),
            )
            .expect("final discovery remains valid with only legacy resources");
        assert_eq!(modern_resources["resources"], serde_json::json!([]));
        let modern_templates = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    "resources/templates/list",
                    Some(serde_json::json!({
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                    })),
                    183_i64,
                ),
            )
            .expect("final template discovery remains valid with only legacy templates");
        assert_eq!(modern_templates["resourceTemplates"], serde_json::json!([]));

        let modern_prompt = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    "prompts/get",
                    Some(serde_json::json!({
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                        "name": "legacy-only-prompt",
                    })),
                    184_i64,
                ),
            )
            .expect_err("changing only the dispatch era refuses the legacy-only prompt");
        assert_eq!(modern_prompt.code, McpErrorCode::InvalidParams);
        assert!(
            !router
                .server_discovery_behavior_registry()
                .contains(ServerBehavior::ResourcesList)
        );
        assert!(
            !router
                .server_discovery_behavior_registry()
                .contains(ServerBehavior::PromptsList)
        );
    }

    // ── add_tool_with_behavior ─────────────────────────────────────────

    #[test]
    fn duplicate_error_warn_and_ignore_preserve_handler_schema_and_order() {
        for behavior in [
            crate::DuplicateBehavior::Error,
            crate::DuplicateBehavior::Warn,
            crate::DuplicateBehavior::Ignore,
        ] {
            let original_legacy_calls = Arc::new(AtomicUsize::new(0));
            let original_final_calls = Arc::new(AtomicUsize::new(0));
            let candidate_legacy_calls = Arc::new(AtomicUsize::new(0));
            let candidate_final_calls = Arc::new(AtomicUsize::new(0));
            let mut router = Router::new();
            router
                .add_tool(NamedTool::new("before"))
                .expect("baseline tool admission succeeds");
            router
                .add_tool(DuplicateInvariantTool {
                    label: "original",
                    schema_property: "original_property",
                    legacy_calls: Arc::clone(&original_legacy_calls),
                    final_calls: Arc::clone(&original_final_calls),
                })
                .expect("original admission succeeds");
            router
                .add_tool(NamedTool::new("after"))
                .expect("trailing tool admission succeeds");

            let cx = Cx::for_testing();
            let state = SessionState::new();
            let request_ctx = request_context(&cx, 81, Budget::INFINITE, &state);
            let legacy_before =
                serde_json::to_value(router.tools()).expect("legacy catalog serializes");
            let modern_before = router
                .dispatch_stateless(
                    &request_ctx,
                    &final_tools_list_request(None, None, None, 81_i64),
                )
                .expect("modern catalog is available");

            let registration = router.add_tool_with_behavior(
                DuplicateInvariantTool {
                    label: "candidate",
                    schema_property: "candidate_property",
                    legacy_calls: Arc::clone(&candidate_legacy_calls),
                    final_calls: Arc::clone(&candidate_final_calls),
                },
                behavior,
            );
            if behavior == crate::DuplicateBehavior::Error {
                let error = registration.expect_err("Error rejects the duplicate");
                assert!(error.message.contains("already exists"));
            } else {
                registration.expect("Warn and Ignore retain the original");
            }

            assert_eq!(
                serde_json::to_value(router.tools()).expect("legacy catalog serializes"),
                legacy_before
            );
            assert_eq!(
                router
                    .dispatch_stateless(
                        &request_ctx,
                        &final_tools_list_request(None, None, None, 82_i64),
                    )
                    .expect("modern catalog remains available"),
                modern_before
            );
            assert_eq!(
                router
                    .tools()
                    .into_iter()
                    .map(|tool| tool.name)
                    .collect::<Vec<_>>(),
                vec!["before", "duplicate-invariant-tool", "after"]
            );

            let legacy = router
                .handle_tools_call(
                    &request_ctx,
                    CallToolParams {
                        name: "duplicate-invariant-tool".to_owned(),
                        arguments: Some(serde_json::json!({})),
                        meta: None,
                    },
                    state.clone(),
                    None,
                    None,
                )
                .expect("legacy dispatch retains the original");
            assert_eq!(
                serde_json::to_value(legacy).expect("legacy result serializes")["content"][0]["text"],
                "original"
            );
            let modern = router
                .dispatch_stateless(
                    &request_ctx,
                    &final_tools_call_request(
                        "duplicate-invariant-tool",
                        serde_json::json!({}),
                        83_i64,
                    ),
                )
                .expect("modern dispatch retains the original");
            assert_eq!(modern["content"][0]["text"], "original");
            assert_eq!(original_legacy_calls.load(Ordering::SeqCst), 1);
            assert_eq!(original_final_calls.load(Ordering::SeqCst), 1);
            assert_eq!(candidate_legacy_calls.load(Ordering::SeqCst), 0);
            assert_eq!(candidate_final_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn duplicate_replace_atomically_updates_handler_schema_and_retains_order() {
        let replacement_legacy_calls = Arc::new(AtomicUsize::new(0));
        let replacement_final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router
            .add_tool(NamedTool::new("before"))
            .expect("baseline admission succeeds");
        router
            .add_tool(DuplicateInvariantTool {
                label: "original",
                schema_property: "original_property",
                legacy_calls: Arc::new(AtomicUsize::new(0)),
                final_calls: Arc::new(AtomicUsize::new(0)),
            })
            .expect("original admission succeeds");
        router
            .add_tool(NamedTool::new("after"))
            .expect("trailing admission succeeds");
        router
            .add_tool_with_behavior(
                DuplicateInvariantTool {
                    label: "replacement",
                    schema_property: "replacement_property",
                    legacy_calls: Arc::clone(&replacement_legacy_calls),
                    final_calls: Arc::clone(&replacement_final_calls),
                },
                crate::DuplicateBehavior::Replace,
            )
            .expect("Replace admits before committing the candidate");

        assert_eq!(
            router
                .tools()
                .into_iter()
                .map(|tool| tool.name)
                .collect::<Vec<_>>(),
            vec!["before", "duplicate-invariant-tool", "after"]
        );
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 84, Budget::INFINITE, &state);
        let modern_catalog = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_list_request(None, None, None, 84_i64),
            )
            .expect("modern replacement catalog is available");
        assert_eq!(
            modern_catalog["tools"][1]["inputSchema"]["properties"],
            serde_json::json!({"replacement_property": {"type": "boolean"}})
        );
        assert_eq!(
            router.tools()[1].description.as_deref(),
            Some("replacement")
        );

        let legacy = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "duplicate-invariant-tool".to_owned(),
                    arguments: Some(serde_json::json!({})),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("legacy dispatch uses replacement");
        assert_eq!(
            serde_json::to_value(legacy).expect("legacy result serializes")["content"][0]["text"],
            "replacement"
        );
        let modern = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "duplicate-invariant-tool",
                    serde_json::json!({}),
                    85_i64,
                ),
            )
            .expect("modern dispatch uses replacement");
        assert_eq!(modern["content"][0]["text"], "replacement");
        assert_eq!(replacement_legacy_calls.load(Ordering::SeqCst), 1);
        assert_eq!(replacement_final_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn add_tool_behavior_new_tool_ok() {
        let mut r = Router::new();
        r.add_tool_with_behavior(NamedTool::new("t"), crate::DuplicateBehavior::Error)
            .unwrap();
        assert_eq!(r.tools_count(), 1);
    }

    // ── add_resource / get_resource ────────────────────────────────────

    #[test]
    fn add_and_get_resource() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a.txt"));
        assert_eq!(r.resources_count(), 1);
        assert!(r.get_resource("file:///a.txt").is_some());
        assert!(r.get_resource("file:///b.txt").is_none());
    }

    #[test]
    fn resources_returns_definitions_in_order() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///b"));
        r.add_resource(NamedResource::new("file:///a"));
        let uris: Vec<_> = r.resources().iter().map(|res| res.uri.clone()).collect();
        assert_eq!(uris, vec!["file:///b", "file:///a"]);
    }

    // ── add_resource_with_behavior ─────────────────────────────────────

    #[test]
    fn add_resource_behavior_error_on_duplicate() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        let err = r
            .add_resource_with_behavior(
                NamedResource::new("file:///a"),
                crate::DuplicateBehavior::Error,
            )
            .unwrap_err();
        assert!(err.message.contains("already exists"));
    }

    #[test]
    fn add_resource_behavior_ignore() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource_with_behavior(
            NamedResource::new("file:///a"),
            crate::DuplicateBehavior::Ignore,
        )
        .unwrap();
        assert_eq!(r.resources_count(), 1);
    }

    // ── add_prompt / get_prompt ────────────────────────────────────────

    #[test]
    fn add_and_get_prompt() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("greet"));
        assert_eq!(r.prompts_count(), 1);
        assert!(r.get_prompt("greet").is_some());
        assert!(r.get_prompt("other").is_none());
    }

    #[test]
    fn prompts_returns_definitions_in_order() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("z"));
        r.add_prompt(NamedPrompt::new("a"));
        let names: Vec<_> = r.prompts().iter().map(|p| p.name.clone()).collect();
        assert_eq!(names, vec!["z", "a"]);
    }

    // ── add_prompt_with_behavior ───────────────────────────────────────

    #[test]
    fn add_prompt_behavior_error_on_duplicate() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        let err = r
            .add_prompt_with_behavior(NamedPrompt::new("p"), crate::DuplicateBehavior::Error)
            .unwrap_err();
        assert!(err.message.contains("already exists"));
    }

    #[test]
    fn add_prompt_behavior_warn_keeps_original() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        r.add_prompt_with_behavior(NamedPrompt::new("p"), crate::DuplicateBehavior::Warn)
            .unwrap();
        assert_eq!(r.prompts_count(), 1);
    }

    #[test]
    fn duplicate_registration_errors_do_not_echo_peer_identifiers() {
        let canary = "raw-peer-identifier-canary";

        let mut tools = Router::new();
        tools
            .add_tool(NamedTool::new(canary))
            .expect("tool registration succeeds");
        let tool_error = tools
            .add_tool_with_behavior(NamedTool::new(canary), crate::DuplicateBehavior::Error)
            .unwrap_err();

        let mut resources = Router::new();
        resources.add_resource(NamedResource::new(canary));
        let resource_error = resources
            .add_resource_with_behavior(NamedResource::new(canary), crate::DuplicateBehavior::Error)
            .unwrap_err();

        let mut templates = Router::new();
        templates.add_resource_template(marked_template(canary, "original"));
        let template_error = templates
            .add_resource_template_with_behavior(
                marked_template(canary, "incoming"),
                crate::DuplicateBehavior::Error,
            )
            .unwrap_err();

        let mut prompts = Router::new();
        prompts.add_prompt(NamedPrompt::new(canary));
        let prompt_error = prompts
            .add_prompt_with_behavior(NamedPrompt::new(canary), crate::DuplicateBehavior::Error)
            .unwrap_err();

        for error in [tool_error, resource_error, template_error, prompt_error] {
            assert!(error.message.contains("already exists"));
            assert!(!error.message.contains(canary));
        }
    }

    // ── add_resource_template ──────────────────────────────────────────

    #[test]
    fn add_resource_template_and_list() {
        let mut r = Router::new();
        let tmpl = ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        r.add_resource_template(tmpl);
        assert_eq!(r.resource_templates_count(), 1);
        assert!(r.get_resource_template("db://{table}").is_some());
        assert!(r.get_resource_template("db://{other}").is_none());
    }

    #[test]
    fn add_resource_template_replaces_existing() {
        let mut r = Router::new();
        let tmpl1 = ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db1".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let tmpl2 = ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db2".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        r.add_resource_template(tmpl1);
        r.add_resource_template(tmpl2);
        assert_eq!(r.resource_templates_count(), 1);
        let tmpl = r.get_resource_template("db://{table}").unwrap();
        assert_eq!(tmpl.name, "db2");
    }

    #[test]
    fn add_resource_template_with_behavior_preserves_or_replaces_identity() {
        for behavior in [
            crate::DuplicateBehavior::Warn,
            crate::DuplicateBehavior::Ignore,
            crate::DuplicateBehavior::Error,
        ] {
            let mut router = Router::new();
            router.add_resource_template(marked_template("peer://{secret}", "original"));
            let result = router.add_resource_template_with_behavior(
                marked_template("peer://{secret}", "incoming"),
                behavior,
            );

            if behavior == crate::DuplicateBehavior::Error {
                let error = result.expect_err("Error policy rejects the duplicate");
                assert!(error.message.contains("already exists"));
                assert!(!error.message.contains("peer://{secret}"));
            } else {
                result.expect("Warn and Ignore keep the original");
            }
            assert_eq!(router.resource_templates_count(), 1);
            assert_eq!(
                router
                    .get_resource_template("peer://{secret}")
                    .expect("original template remains")
                    .name,
                "original"
            );
        }

        let mut router = Router::new();
        router.add_resource_template(marked_template("peer://{secret}", "original"));
        router
            .add_resource_template_with_behavior(
                marked_template("peer://{secret}", "incoming"),
                crate::DuplicateBehavior::Replace,
            )
            .expect("Replace accepts the duplicate");
        assert_eq!(router.resource_templates_count(), 1);
        assert_eq!(
            router
                .get_resource_template("peer://{secret}")
                .expect("replacement template exists")
                .name,
            "incoming"
        );
    }

    // ── resource_exists / resolve_resource ──────────────────────────────

    #[test]
    fn resource_exists_for_static_resource() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a.txt"));
        assert!(r.resource_exists("file:///a.txt"));
        assert!(!r.resource_exists("file:///b.txt"));
    }

    // ── strict_input_validation ────────────────────────────────────────

    #[test]
    fn strict_input_validation_default_off() {
        let r = Router::new();
        assert!(!r.strict_input_validation());
    }

    #[test]
    fn set_strict_input_validation() {
        let mut r = Router::new();
        r.set_strict_input_validation(true);
        assert!(r.strict_input_validation());
        r.set_strict_input_validation(false);
        assert!(!r.strict_input_validation());
    }

    // ── set_list_page_size ─────────────────────────────────────────────

    #[test]
    fn set_list_page_size_zero_treated_as_none() {
        let mut r = Router::new();
        r.set_list_page_size(Some(0));
        // Zero page size is filtered to None
        assert!(r.list_page_size.is_none());
    }

    #[test]
    fn set_list_page_size_positive() {
        let mut r = Router::new();
        r.set_list_page_size(Some(10));
        assert_eq!(r.list_page_size, Some(10));
    }

    #[test]
    fn set_list_page_size_none() {
        let mut r = Router::new();
        r.set_list_page_size(Some(10));
        r.set_list_page_size(None);
        assert!(r.list_page_size.is_none());
    }

    // ── tools_filtered ─────────────────────────────────────────────────

    #[test]
    fn tools_filtered_no_filters_returns_all() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("a"))
            .expect("tool registration succeeds");
        r.add_tool(NamedTool::new("b"))
            .expect("tool registration succeeds");
        let tools = r.tools_filtered(None, None);
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn tools_filtered_by_session_state_disables() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("a"))
            .expect("tool registration succeeds");
        r.add_tool(NamedTool::new("b"))
            .expect("tool registration succeeds");
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> = ["a".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_tools", &disabled);
        let tools = r.tools_filtered(Some(&state), None);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "b");
    }

    #[test]
    fn tools_filtered_by_tags() {
        let mut r = Router::new();
        r.add_tool(NamedTool::with_tags("a", vec!["db".to_string()]))
            .expect("tool registration succeeds");
        r.add_tool(NamedTool::with_tags("b", vec!["web".to_string()]))
            .expect("tool registration succeeds");
        let include = vec!["db".to_string()];
        let filters = TagFilters::new(Some(&include), None);
        let tools = r.tools_filtered(None, Some(&filters));
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "a");
    }

    // ── resources_filtered ─────────────────────────────────────────────

    #[test]
    fn resources_filtered_by_session_state() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource(NamedResource::new("file:///b"));
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["file:///a".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_resources", &disabled);
        let res = r.resources_filtered(Some(&state), None);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].uri, "file:///b");
    }

    // ── prompts_filtered ───────────────────────────────────────────────

    #[test]
    fn prompts_filtered_by_session_state() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("a"));
        r.add_prompt(NamedPrompt::new("b"));
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> = ["a".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_prompts", &disabled);
        let prompts = r.prompts_filtered(Some(&state), None);
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "b");
    }

    #[test]
    fn prompts_filtered_by_tags() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::with_tags("a", vec!["internal".to_string()]));
        r.add_prompt(NamedPrompt::with_tags("b", vec!["public".to_string()]));
        let exclude = vec!["internal".to_string()];
        let filters = TagFilters::new(None, Some(&exclude));
        let prompts = r.prompts_filtered(None, Some(&filters));
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "b");
    }

    // ── resource_templates_filtered ────────────────────────────────────

    #[test]
    fn resource_templates_filtered_by_session_state() {
        let mut r = Router::new();
        r.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["admin".to_string()],
        });
        r.add_resource_template(ResourceTemplate {
            uri_template: "cache://{key}".to_string(),
            name: "cache".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["db://{table}".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_resources", &disabled);
        let tmpls = r.resource_templates_filtered(Some(&state), None);
        assert_eq!(tmpls.len(), 1);
        assert_eq!(tmpls[0].name, "cache");
    }

    // ── apply_prefix / validate_prefix ─────────────────────────────────

    #[test]
    fn apply_prefix_with_prefix() {
        assert_eq!(Router::apply_prefix("tool", Some("ns")), "ns/tool");
    }

    #[test]
    fn apply_prefix_no_prefix() {
        assert_eq!(Router::apply_prefix("tool", None), "tool");
    }

    #[test]
    fn apply_prefix_empty_prefix() {
        assert_eq!(Router::apply_prefix("tool", Some("")), "tool");
    }

    #[test]
    fn validate_prefix_valid() {
        assert!(Router::validate_prefix("my-prefix_1").is_ok());
    }

    #[test]
    fn validate_prefix_empty_is_ok() {
        assert!(Router::validate_prefix("").is_ok());
    }

    #[test]
    fn validate_prefix_rejects_slashes() {
        let err = Router::validate_prefix("a/b").unwrap_err();
        assert!(err.contains("slashes"));
    }

    #[test]
    fn validate_prefix_rejects_special_chars() {
        let err = Router::validate_prefix("a@b").unwrap_err();
        assert!(err.contains("invalid character"));
    }

    // ── MountResult ────────────────────────────────────────────────────

    #[test]
    fn mount_result_default_has_no_components() {
        let r = MountResult::default();
        assert!(!r.has_components());
        assert!(r.is_success());
    }

    #[test]
    fn mount_result_with_tools_has_components() {
        let mut r = MountResult::default();
        r.tools = 1;
        assert!(r.has_components());
    }

    #[test]
    fn mount_result_debug() {
        let r = MountResult::default();
        let debug = format!("{:?}", r);
        assert!(debug.contains("MountResult"));
    }

    // ── mount ──────────────────────────────────────────────────────────

    #[test]
    fn mount_tools_with_prefix() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("query"))
            .expect("tool registration succeeds");
        let result = main.mount(sub, Some("db"));
        assert_eq!(result.tools, 1);
        assert!(main.get_tool("db/query").is_some());
        assert!(main.get_tool("query").is_none());
    }

    #[test]
    fn mount_without_prefix() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("query"))
            .expect("tool registration succeeds");
        let result = main.mount(sub, None);
        assert_eq!(result.tools, 1);
        assert!(main.get_tool("query").is_some());
    }

    #[test]
    fn mount_resources_with_prefix() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_resource(NamedResource::new("file:///a"));
        let result = main.mount(sub, Some("ns"));
        assert_eq!(result.resources, 1);
        assert!(main.get_resource("ns/file:///a").is_some());

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let read = main
            .handle_resources_read(
                &request_ctx,
                &ReadResourceParams {
                    uri: "ns/file:///a".to_string(),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("mounted resource is readable through its public URI");
        let [
            LegacyResourceContent::Text {
                uri,
                text,
                additional,
                ..
            },
        ] = read.contents.as_slice()
        else {
            panic!("mounted resource must retain the exact legacy text shape");
        };
        assert_eq!(uri, "ns/file:///a");
        assert_eq!(text, "content");
        assert!(additional.is_empty());
    }

    #[test]
    fn mounting_resource_does_not_requery_one_shot_definition() {
        let mut source = Router::new();
        source.add_resource(DefinitionPanicResource(std::sync::atomic::AtomicBool::new(
            false,
        )));
        let mut destination = Router::new();

        let result = destination.mount_resources(source, Some("ns"));

        assert!(result.is_success());
        assert_eq!(result.resources, 1);
        assert!(destination.get_resource("ns/panic://definition").is_some());
    }

    #[test]
    fn mounting_resource_template_does_not_requery_one_shot_template() {
        let mut source = Router::new();
        source.add_resource(TemplatePanicResource(std::sync::atomic::AtomicBool::new(
            false,
        )));
        let mut destination = Router::new();

        let result = destination.mount_resources(source, Some("ns"));

        assert!(result.is_success());
        assert_eq!(result.resource_templates, 1);
        assert!(
            destination
                .get_resource_template("ns/panic-template://{id}")
                .is_some()
        );
    }

    #[test]
    fn nested_resource_mounts_translate_both_namespace_layers() {
        let mut leaf = Router::new();
        leaf.add_resource(NamedResource::new("file:///a"));

        let mut middle = Router::new();
        assert!(middle.mount(leaf, Some("ns")).is_success());
        let mut outer = Router::new();
        assert!(outer.mount(middle, Some("ns")).is_success());

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let read = outer
            .handle_resources_read(
                &request_ctx,
                &ReadResourceParams {
                    uri: "ns/ns/file:///a".to_string(),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("nested mounted resource is readable");
        let [
            LegacyResourceContent::Text {
                uri,
                text,
                additional,
                ..
            },
        ] = read.contents.as_slice()
        else {
            panic!("nested mounted resource must retain the exact legacy text shape");
        };
        assert_eq!(uri, "ns/ns/file:///a");
        assert_eq!(text, "content");
        assert!(additional.is_empty());
    }

    #[test]
    fn nested_resource_template_mounts_translate_every_namespace_layer() {
        struct TemplatedResource;

        impl ResourceHandler for TemplatedResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "db://placeholder".to_string(),
                    name: "database".to_string(),
                    description: None,
                    mime_type: Some("text/plain".to_string()),
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }

            fn template(&self) -> Option<ResourceTemplate> {
                Some(ResourceTemplate {
                    uri_template: "db://{table}".to_string(),
                    name: "database".to_string(),
                    description: None,
                    mime_type: Some("text/plain".to_string()),
                    icon: None,
                    version: None,
                    tags: vec![],
                })
            }

            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                unreachable!("templated reads use read_with_uri")
            }

            fn read_with_uri(
                &self,
                _ctx: &McpContext,
                uri: &str,
                params: &UriParams,
            ) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![ResourceContent {
                    uri: uri.to_string(),
                    mime_type: Some("text/plain".to_string()),
                    text: params.get("table").cloned(),
                    blob: None,
                }])
            }
        }

        let mut source = Router::new();
        source.add_resource(TemplatedResource);
        let mut middle = Router::new();
        assert!(middle.mount_resources(source, Some("peer")).is_success());
        let mut mounted = Router::new();
        assert!(mounted.mount_resources(middle, Some("peer")).is_success());

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let read = mounted
            .handle_resources_read(
                &request_ctx,
                &ReadResourceParams {
                    uri: "peer/peer/db://users".to_string(),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("mounted template is readable through its public URI");
        let [
            LegacyResourceContent::Text {
                uri,
                text,
                additional,
                ..
            },
        ] = read.contents.as_slice()
        else {
            panic!("mounted template must retain the exact legacy text shape");
        };
        assert_eq!(uri, "peer/peer/db://users");
        assert_eq!(text, "users");
        assert!(additional.is_empty());
    }

    #[test]
    fn handle_resources_read_resolves_true_async_mounted_template_and_translates_uri() {
        struct AsyncTemplatedResource {
            observed: Arc<Mutex<Option<(String, String)>>>,
        }

        impl ResourceHandler for AsyncTemplatedResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "async-db://placeholder".to_string(),
                    name: "async-database".to_string(),
                    description: None,
                    mime_type: Some("text/plain".to_string()),
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }

            fn template(&self) -> Option<ResourceTemplate> {
                Some(ResourceTemplate {
                    uri_template: "async-db://{table}".to_string(),
                    name: "async-database".to_string(),
                    description: None,
                    mime_type: Some("text/plain".to_string()),
                    icon: None,
                    version: None,
                    tags: vec![],
                })
            }

            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                unreachable!("router must dispatch templated resources through the async override")
            }

            fn read_with_uri(
                &self,
                _ctx: &McpContext,
                _uri: &str,
                _params: &UriParams,
            ) -> McpResult<Vec<ResourceContent>> {
                unreachable!("router must not fall back to the synchronous templated read")
            }

            fn read_async_with_uri<'a>(
                &'a self,
                _ctx: &'a McpContext,
                uri: &'a str,
                params: &'a UriParams,
            ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
                Box::pin(async move {
                    let mut first_poll = true;
                    std::future::poll_fn(move |waker| {
                        if std::mem::take(&mut first_poll) {
                            waker.waker().wake_by_ref();
                            std::task::Poll::Pending
                        } else {
                            std::task::Poll::Ready(())
                        }
                    })
                    .await;
                    let Some(table) = params.get("table").cloned() else {
                        return Outcome::Err(McpError::invalid_params(
                            "mounted template did not resolve its table parameter",
                        ));
                    };
                    *self.observed.lock().expect("observation mutex poisoned") =
                        Some((uri.to_string(), table.clone()));
                    Outcome::Ok(vec![ResourceContent {
                        uri: uri.to_string(),
                        mime_type: Some("text/plain".to_string()),
                        text: Some(format!("async table {table}")),
                        blob: None,
                    }])
                })
            }
        }

        let observed = Arc::new(Mutex::new(None));
        let mut source = Router::new();
        source.add_resource(AsyncTemplatedResource {
            observed: Arc::clone(&observed),
        });
        let mut mounted = Router::new();
        let mount_result = mounted.mount_resources(source, Some("peer"));
        assert!(mount_result.is_success());
        assert_eq!(mount_result.resource_templates, 1);

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let read = mounted
            .handle_resources_read(
                &request_ctx,
                &ReadResourceParams {
                    uri: "peer/async-db://users".to_string(),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("true-async mounted template is readable through its public URI");

        assert_eq!(read.contents.len(), 1);
        let [
            LegacyResourceContent::Text {
                uri,
                text,
                additional,
                ..
            },
        ] = read.contents.as_slice()
        else {
            panic!("async mounted template must retain the exact legacy text shape");
        };
        assert_eq!(uri, "peer/async-db://users");
        assert_eq!(text, "async table users");
        assert!(additional.is_empty());
        assert_eq!(
            *observed.lock().expect("observation mutex poisoned"),
            Some(("async-db://users".to_string(), "users".to_string()))
        );
    }

    #[test]
    fn mount_prompts_with_prefix() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_prompt(NamedPrompt::new("greet"));
        let result = main.mount(sub, Some("ns"));
        assert_eq!(result.prompts, 1);
        assert!(main.get_prompt("ns/greet").is_some());
    }

    #[test]
    fn mount_warns_on_conflict() {
        let mut main = Router::new();
        main.add_tool(NamedTool::new("t"))
            .expect("tool registration succeeds");
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("t"))
            .expect("tool registration succeeds");
        let result = main.mount(sub, None);
        assert_eq!(result.tools, 1);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("already exists"));
    }

    #[test]
    fn mount_rejects_invalid_prefix_without_mutating() {
        let mut main = Router::new();
        main.add_tool(NamedTool::new("original"))
            .expect("tool registration succeeds");
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("incoming"))
            .expect("tool registration succeeds");
        let result = main.mount(sub, Some("bad/prefix"));
        assert!(!result.is_success());
        assert_eq!(result.tools, 0);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("slashes"));
        assert!(!result.errors[0].contains("bad/prefix"));
        assert_eq!(main.tools_count(), 1);
        assert!(main.get_tool("original").is_some());
        assert!(main.get_tool("bad/prefix/incoming").is_none());
    }

    #[test]
    fn mount_with_behavior_honors_policy_for_every_component_kind() {
        for behavior in [
            crate::DuplicateBehavior::Warn,
            crate::DuplicateBehavior::Ignore,
            crate::DuplicateBehavior::Replace,
            crate::DuplicateBehavior::Error,
        ] {
            let mut main = marked_router("original");
            let mut sub = marked_router("incoming");
            if behavior == crate::DuplicateBehavior::Error {
                sub.add_tool(NamedTool::new("unique_tool"))
                    .expect("tool registration succeeds");
            }

            let result = main.mount_with_behavior(sub, None, behavior);
            let replaced = behavior == crate::DuplicateBehavior::Replace;
            let rejected = behavior == crate::DuplicateBehavior::Error;
            let expected_mounted = if replaced { 1 } else { 0 };

            assert_eq!(result.is_success(), !rejected);
            assert_eq!(result.tools, expected_mounted);
            assert_eq!(result.resources, expected_mounted);
            assert_eq!(result.resource_templates, expected_mounted);
            assert_eq!(result.prompts, expected_mounted);
            assert_eq!(result.errors.len(), if rejected { 4 } else { 0 });
            assert_eq!(
                result.warnings.len(),
                if matches!(
                    behavior,
                    crate::DuplicateBehavior::Warn | crate::DuplicateBehavior::Replace
                ) {
                    4
                } else {
                    0
                }
            );
            assert_router_marker(&main, if replaced { "incoming" } else { "original" });
            assert!(main.get_tool("unique_tool").is_none());

            for message in result.warnings.iter().chain(&result.errors) {
                assert!(!message.contains("duplicate_tool"));
                assert!(!message.contains("duplicate://resource"));
                assert!(!message.contains("duplicate://{item}"));
                assert!(!message.contains("duplicate_prompt"));
            }
        }
    }

    #[test]
    fn behavior_aware_partial_mounts_preflight_error_atomically() {
        let mut tools = Router::new();
        tools
            .add_tool(NamedTool::with_tags("same", vec!["original".to_string()]))
            .expect("tool registration succeeds");
        let mut tool_source = Router::new();
        tool_source
            .add_tool(NamedTool::with_tags("same", vec!["incoming".to_string()]))
            .expect("tool registration succeeds");
        tool_source
            .add_tool(NamedTool::new("unique"))
            .expect("tool registration succeeds");
        let tool_result =
            tools.mount_tools_with_behavior(tool_source, None, crate::DuplicateBehavior::Error);
        assert!(!tool_result.is_success());
        assert_eq!(tool_result.tools, 0);
        assert_eq!(tools.tools_count(), 1);
        assert_eq!(
            tools.get_tool("same").unwrap().definition().tags,
            vec!["original".to_string()]
        );
        assert!(tools.get_tool("unique").is_none());

        let mut resources = Router::new();
        resources.add_resource(NamedResource::with_tags(
            "same://resource",
            vec!["original".to_string()],
        ));
        let mut resource_source = Router::new();
        resource_source.add_resource(NamedResource::with_tags(
            "same://resource",
            vec!["incoming".to_string()],
        ));
        resource_source.add_resource_template(marked_template("unique://{item}", "incoming"));
        let resource_result = resources.mount_resources_with_behavior(
            resource_source,
            None,
            crate::DuplicateBehavior::Error,
        );
        assert!(!resource_result.is_success());
        assert_eq!(resource_result.resources, 0);
        assert_eq!(resource_result.resource_templates, 0);
        assert_eq!(resources.resources_count(), 1);
        assert_eq!(resources.resource_templates_count(), 0);
        assert_eq!(
            resources
                .get_resource("same://resource")
                .unwrap()
                .definition()
                .tags,
            vec!["original".to_string()]
        );

        let mut prompts = Router::new();
        prompts.add_prompt(NamedPrompt::with_tags("same", vec!["original".to_string()]));
        let mut prompt_source = Router::new();
        prompt_source.add_prompt(NamedPrompt::with_tags("same", vec!["incoming".to_string()]));
        prompt_source.add_prompt(NamedPrompt::new("unique"));
        let prompt_result = prompts.mount_prompts_with_behavior(
            prompt_source,
            None,
            crate::DuplicateBehavior::Error,
        );
        assert!(!prompt_result.is_success());
        assert_eq!(prompt_result.prompts, 0);
        assert_eq!(prompts.prompts_count(), 1);
        assert_eq!(
            prompts.get_prompt("same").unwrap().definition().tags,
            vec!["original".to_string()]
        );
        assert!(prompts.get_prompt("unique").is_none());
    }

    #[test]
    fn full_error_mount_is_atomic_across_component_kinds() {
        let mut main = Router::new();
        main.add_tool(NamedTool::with_tags(
            "conflict",
            vec!["original".to_string()],
        ))
        .expect("tool registration succeeds");

        let mut sub = Router::new();
        sub.add_tool(NamedTool::with_tags(
            "conflict",
            vec!["incoming".to_string()],
        ))
        .expect("tool registration succeeds");
        sub.add_resource(NamedResource::new("unique://resource"));
        sub.add_resource_template(marked_template("unique://{item}", "incoming"));
        sub.add_prompt(NamedPrompt::new("unique_prompt"));

        let result = main.mount_with_behavior(sub, None, crate::DuplicateBehavior::Error);
        assert!(!result.is_success());
        assert_eq!(result.errors.len(), 1);
        assert!(!result.has_components());
        assert_eq!(main.tools_count(), 1);
        assert_eq!(main.resources_count(), 0);
        assert_eq!(main.resource_templates_count(), 0);
        assert_eq!(main.prompts_count(), 0);
        assert_eq!(
            main.get_tool("conflict").unwrap().definition().tags,
            vec!["original".to_string()]
        );
    }

    #[test]
    fn invalid_prefix_rejects_every_partial_mount_without_mutation() {
        let mut tools = Router::new();
        let mut tool_source = Router::new();
        tool_source
            .add_tool(NamedTool::new("tool"))
            .expect("tool registration succeeds");
        let tool_result = tools.mount_tools_with_behavior(
            tool_source,
            Some("peer/secret"),
            crate::DuplicateBehavior::Replace,
        );
        assert!(!tool_result.is_success());
        assert_eq!(tools.tools_count(), 0);

        let mut resources = Router::new();
        let mut resource_source = Router::new();
        resource_source.add_resource(NamedResource::new("resource://value"));
        resource_source.add_resource_template(marked_template("template://{value}", "incoming"));
        let resource_result = resources.mount_resources_with_behavior(
            resource_source,
            Some("peer/secret"),
            crate::DuplicateBehavior::Replace,
        );
        assert!(!resource_result.is_success());
        assert_eq!(resources.resources_count(), 0);
        assert_eq!(resources.resource_templates_count(), 0);

        let mut prompts = Router::new();
        let mut prompt_source = Router::new();
        prompt_source.add_prompt(NamedPrompt::new("prompt"));
        let prompt_result = prompts.mount_prompts_with_behavior(
            prompt_source,
            Some("peer/secret"),
            crate::DuplicateBehavior::Replace,
        );
        assert!(!prompt_result.is_success());
        assert_eq!(prompts.prompts_count(), 0);

        for result in [tool_result, resource_result, prompt_result] {
            assert_eq!(result.errors.len(), 1);
            assert!(!result.errors[0].contains("peer/secret"));
            assert!(!result.has_components());
        }
    }

    // ── mount_tools / mount_resources / mount_prompts ──────────────────

    #[test]
    fn mount_tools_only() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("t1"))
            .expect("tool registration succeeds");
        sub.add_prompt(NamedPrompt::new("p1"));
        let result = main.mount_tools(sub, Some("ns"));
        assert_eq!(result.tools, 1);
        assert!(main.get_tool("ns/t1").is_some());
        assert_eq!(main.prompts_count(), 0); // prompts not mounted
    }

    #[test]
    fn mount_prompts_only() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("t1"))
            .expect("tool registration succeeds");
        sub.add_prompt(NamedPrompt::new("p1"));
        let result = main.mount_prompts(sub, Some("ns"));
        assert_eq!(result.prompts, 1);
        assert!(main.get_prompt("ns/p1").is_some());
        assert_eq!(main.tools_count(), 0); // tools not mounted
    }

    // ── handle_tools_list pagination ───────────────────────────────────

    #[test]
    fn handle_tools_list_no_pagination() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("a"))
            .expect("tool registration succeeds");
        r.add_tool(NamedTool::new("b"))
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let params = ListToolsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.tools.len(), 2);
        assert!(result.next_cursor.is_none());
    }

    #[test]
    fn handle_tools_list_with_pagination() {
        let mut r = Router::new();
        r.set_list_page_size(Some(1));
        r.add_tool(NamedTool::new("a"))
            .expect("tool registration succeeds");
        r.add_tool(NamedTool::new("b"))
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let request_ctx = McpContext::new(cx, 1);

        // First page
        let params = ListToolsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "a");
        assert!(result.next_cursor.is_some());

        // Second page
        let params = ListToolsParams {
            cursor: result.next_cursor,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "b");
        assert!(result.next_cursor.is_none());
    }

    #[test]
    fn handle_tools_list_with_tag_filter() {
        let mut r = Router::new();
        r.add_tool(NamedTool::with_tags("a", vec!["db".to_string()]))
            .expect("tool registration succeeds");
        r.add_tool(NamedTool::with_tags("b", vec!["web".to_string()]))
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let params = ListToolsParams {
            cursor: None,
            include_tags: Some(vec!["db".to_string()]),
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "a");
    }

    // ── handle_resources_list pagination ───────────────────────────────

    #[test]
    fn handle_resources_list_no_pagination() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        let cx = Cx::for_testing();
        let params = ListResourcesParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_resources_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.resources.len(), 1);
        assert!(result.next_cursor.is_none());
    }

    #[test]
    fn handle_resources_list_with_pagination() {
        let mut r = Router::new();
        r.set_list_page_size(Some(1));
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource(NamedResource::new("file:///b"));
        let cx = Cx::for_testing();
        let params = ListResourcesParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_resources_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.resources.len(), 1);
        assert!(result.next_cursor.is_some());
    }

    // ── handle_prompts_list pagination ─────────────────────────────────

    #[test]
    fn handle_prompts_list_no_pagination() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("greet"));
        let cx = Cx::for_testing();
        let params = ListPromptsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_prompts_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.prompts.len(), 1);
        assert!(result.next_cursor.is_none());
    }

    // ── handle_resource_templates_list ──────────────────────────────────

    #[test]
    fn handle_resource_templates_list_no_pagination() {
        let mut r = Router::new();
        r.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let cx = Cx::for_testing();
        let params = ListResourceTemplatesParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r
            .handle_resource_templates_list(&request_ctx, params, None)
            .unwrap();
        assert_eq!(result.resource_templates.len(), 1);
        assert!(result.next_cursor.is_none());
    }

    // ── handle_initialize ──────────────────────────────────────────────

    #[test]
    fn handle_initialize_returns_protocol_version() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let mut session = Session::new(
            fastmcp_protocol::ServerInfo {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
            fastmcp_protocol::ServerCapabilities::default(),
        );
        let params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: fastmcp_protocol::ClientCapabilities::default(),
            client_info: fastmcp_protocol::ClientInfo {
                name: "test-client".to_string(),
                version: "1.0".to_string(),
            },
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r
            .handle_initialize(
                &request_ctx,
                &mut session,
                params,
                Some("test instructions"),
            )
            .unwrap();
        assert_eq!(result.protocol_version, PROTOCOL_VERSION);
        assert_eq!(result.server_info.name, "test");
        assert_eq!(result.instructions.as_deref(), Some("test instructions"));
    }

    #[test]
    fn handle_initialize_no_instructions() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let mut session = Session::new(
            fastmcp_protocol::ServerInfo {
                name: "srv".to_string(),
                version: "0.1".to_string(),
            },
            fastmcp_protocol::ServerCapabilities::default(),
        );
        let params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: fastmcp_protocol::ClientCapabilities::default(),
            client_info: fastmcp_protocol::ClientInfo {
                name: "c".to_string(),
                version: "0.1".to_string(),
            },
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r
            .handle_initialize(&request_ctx, &mut session, params, None)
            .unwrap();
        assert!(result.instructions.is_none());
    }

    // ── add_resource_with_behavior (Warn / Replace) ─────────────────────

    #[test]
    fn add_resource_behavior_warn_keeps_original() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource_with_behavior(
            NamedResource::new("file:///a"),
            crate::DuplicateBehavior::Warn,
        )
        .unwrap();
        assert_eq!(r.resources_count(), 1);
    }

    #[test]
    fn add_resource_behavior_replace() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource_with_behavior(
            NamedResource::new("file:///a"),
            crate::DuplicateBehavior::Replace,
        )
        .unwrap();
        assert_eq!(r.resources_count(), 1);
    }

    #[test]
    fn add_resource_behavior_new_resource_ok() {
        let mut r = Router::new();
        r.add_resource_with_behavior(
            NamedResource::new("file:///a"),
            crate::DuplicateBehavior::Error,
        )
        .unwrap();
        assert_eq!(r.resources_count(), 1);
    }

    // ── add_prompt_with_behavior (Replace / Ignore / new) ───────────────

    #[test]
    fn add_prompt_behavior_replace() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        r.add_prompt_with_behavior(NamedPrompt::new("p"), crate::DuplicateBehavior::Replace)
            .unwrap();
        assert_eq!(r.prompts_count(), 1);
    }

    #[test]
    fn add_prompt_behavior_ignore() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        r.add_prompt_with_behavior(NamedPrompt::new("p"), crate::DuplicateBehavior::Ignore)
            .unwrap();
        assert_eq!(r.prompts_count(), 1);
    }

    #[test]
    fn add_prompt_behavior_new_prompt_ok() {
        let mut r = Router::new();
        r.add_prompt_with_behavior(NamedPrompt::new("p"), crate::DuplicateBehavior::Error)
            .unwrap();
        assert_eq!(r.prompts_count(), 1);
    }

    // ── add_resource / add_prompt duplicate replace ─────────────────────

    #[test]
    fn add_resource_replaces_on_duplicate() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource(NamedResource::new("file:///a"));
        assert_eq!(r.resources_count(), 1);
        assert_eq!(r.resources().len(), 1);
    }

    #[test]
    fn add_prompt_replaces_on_duplicate() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        r.add_prompt(NamedPrompt::new("p"));
        assert_eq!(r.prompts_count(), 1);
        assert_eq!(r.prompts().len(), 1);
    }

    // ── resource_exists for template match ──────────────────────────────

    #[test]
    fn resource_exists_for_template_match() {
        struct DbResource;
        impl ResourceHandler for DbResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "db://placeholder".to_string(),
                    name: "db".to_string(),
                    description: None,
                    mime_type: Some("text/plain".to_string()),
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }
            fn template(&self) -> Option<ResourceTemplate> {
                Some(ResourceTemplate {
                    uri_template: "db://{table}".to_string(),
                    name: "db".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                })
            }
            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<fastmcp_protocol::ResourceContent>> {
                Ok(vec![])
            }
        }
        let mut r = Router::new();
        r.add_resource(DbResource);
        assert!(r.resource_exists("db://users"));
        assert!(!r.resource_exists("file://other"));
    }

    // ── resources_filtered by tags ──────────────────────────────────────

    #[test]
    fn resources_filtered_by_tags() {
        let mut r = Router::new();
        r.add_resource(NamedResource::with_tags(
            "file:///a",
            vec!["internal".to_string()],
        ));
        r.add_resource(NamedResource::with_tags(
            "file:///b",
            vec!["public".to_string()],
        ));
        let include = vec!["public".to_string()];
        let filters = TagFilters::new(Some(&include), None);
        let res = r.resources_filtered(None, Some(&filters));
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].uri, "file:///b");
    }

    // ── resource_templates_filtered by tags ─────────────────────────────

    #[test]
    fn resource_templates_filtered_by_tags() {
        let mut r = Router::new();
        r.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["admin".to_string()],
        });
        r.add_resource_template(ResourceTemplate {
            uri_template: "cache://{key}".to_string(),
            name: "cache".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["public".to_string()],
        });
        let exclude = vec!["admin".to_string()];
        let filters = TagFilters::new(None, Some(&exclude));
        let tmpls = r.resource_templates_filtered(None, Some(&filters));
        assert_eq!(tmpls.len(), 1);
        assert_eq!(tmpls[0].name, "cache");
    }

    // ── handle_tools_list with session state ────────────────────────────

    #[test]
    fn handle_tools_list_with_session_state_filter() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("a"))
            .expect("tool registration succeeds");
        r.add_tool(NamedTool::new("b"))
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> = ["a".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_tools", &disabled);
        let params = ListToolsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let result = r
            .handle_tools_list(&request_ctx, params, Some(&state))
            .unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "b");
    }

    // ── handle_resources_list with tag filter ────────────────────────────

    #[test]
    fn handle_resources_list_with_tag_filter() {
        let mut r = Router::new();
        r.add_resource(NamedResource::with_tags(
            "file:///a",
            vec!["db".to_string()],
        ));
        r.add_resource(NamedResource::with_tags(
            "file:///b",
            vec!["web".to_string()],
        ));
        let cx = Cx::for_testing();
        let params = ListResourcesParams {
            cursor: None,
            include_tags: Some(vec!["web".to_string()]),
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_resources_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.resources[0].uri, "file:///b");
    }

    // ── handle_prompts_list with pagination ──────────────────────────────

    #[test]
    fn handle_prompts_list_with_pagination() {
        let mut r = Router::new();
        r.set_list_page_size(Some(1));
        r.add_prompt(NamedPrompt::new("a"));
        r.add_prompt(NamedPrompt::new("b"));
        let cx = Cx::for_testing();
        let params = ListPromptsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_prompts_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.prompts.len(), 1);
        assert_eq!(result.prompts[0].name, "a");
        assert!(result.next_cursor.is_some());

        let params = ListPromptsParams {
            cursor: result.next_cursor,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r.handle_prompts_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.prompts.len(), 1);
        assert_eq!(result.prompts[0].name, "b");
        assert!(result.next_cursor.is_none());
    }

    // ── handle_prompts_list with tag filter ──────────────────────────────

    #[test]
    fn handle_prompts_list_with_tag_filter() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::with_tags("a", vec!["internal".to_string()]));
        r.add_prompt(NamedPrompt::with_tags("b", vec!["public".to_string()]));
        let cx = Cx::for_testing();
        let params = ListPromptsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: Some(vec!["internal".to_string()]),
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_prompts_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.prompts.len(), 1);
        assert_eq!(result.prompts[0].name, "b");
    }

    // ── handle_resource_templates_list with pagination ───────────────────

    #[test]
    fn handle_resource_templates_list_with_pagination() {
        let mut r = Router::new();
        r.set_list_page_size(Some(1));
        r.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        r.add_resource_template(ResourceTemplate {
            uri_template: "cache://{key}".to_string(),
            name: "cache".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let cx = Cx::for_testing();
        let request_ctx = McpContext::new(cx, 1);
        let params = ListResourceTemplatesParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r
            .handle_resource_templates_list(&request_ctx, params, None)
            .unwrap();
        assert_eq!(result.resource_templates.len(), 1);
        assert!(result.next_cursor.is_some());

        let params = ListResourceTemplatesParams {
            cursor: result.next_cursor,
            include_tags: None,
            exclude_tags: None,
        };
        let result = r
            .handle_resource_templates_list(&request_ctx, params, None)
            .unwrap();
        assert_eq!(result.resource_templates.len(), 1);
        assert!(result.next_cursor.is_none());
    }

    // ── handle_resource_templates_list with tag filter ───────────────────

    #[test]
    fn handle_resource_templates_list_with_tag_filter() {
        let mut r = Router::new();
        r.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["admin".to_string()],
        });
        r.add_resource_template(ResourceTemplate {
            uri_template: "cache://{key}".to_string(),
            name: "cache".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["public".to_string()],
        });
        let cx = Cx::for_testing();
        let params = ListResourceTemplatesParams {
            cursor: None,
            include_tags: Some(vec!["public".to_string()]),
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r
            .handle_resource_templates_list(&request_ctx, params, None)
            .unwrap();
        assert_eq!(result.resource_templates.len(), 1);
        assert_eq!(result.resource_templates[0].name, "cache");
    }

    // ── mount_resources (selective method) ───────────────────────────────

    #[test]
    fn mount_resources_only() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_resource(NamedResource::new("file:///a"));
        sub.add_tool(NamedTool::new("t1"))
            .expect("tool registration succeeds");
        sub.add_resource_template(ResourceTemplate {
            uri_template: "db://{t}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let result = main.mount_resources(sub, Some("ns"));
        assert_eq!(result.resources, 1);
        assert_eq!(result.resource_templates, 1);
        assert!(main.get_resource("ns/file:///a").is_some());
        assert_eq!(main.tools_count(), 0); // tools not mounted
    }

    // ── MountResult has_components with all fields ──────────────────────

    #[test]
    fn mount_result_with_resources_has_components() {
        let mut r = MountResult::default();
        r.resources = 1;
        assert!(r.has_components());
    }

    #[test]
    fn mount_result_with_templates_has_components() {
        let mut r = MountResult::default();
        r.resource_templates = 1;
        assert!(r.has_components());
    }

    #[test]
    fn mount_result_with_prompts_has_components() {
        let mut r = MountResult::default();
        r.prompts = 1;
        assert!(r.has_components());
    }

    #[test]
    fn mount_result_is_success_with_warnings() {
        let mut r = MountResult::default();
        r.warnings.push("something".to_string());
        assert!(r.is_success());
    }

    #[test]
    fn mount_result_reports_errors_as_failure() {
        let mut result = MountResult::default();
        result.errors.push("mount rejected".to_string());
        assert!(!result.is_success());
        assert!(!result.has_components());
    }

    // ── mount with all component types ──────────────────────────────────

    #[test]
    fn mount_all_component_types() {
        let mut main = Router::new();
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("t1"))
            .expect("tool registration succeeds");
        sub.add_resource(NamedResource::new("file:///r1"));
        sub.add_prompt(NamedPrompt::new("p1"));
        sub.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let result = main.mount(sub, Some("ns"));
        assert_eq!(result.tools, 1);
        assert_eq!(result.resources, 1);
        assert_eq!(result.prompts, 1);
        assert_eq!(result.resource_templates, 1);
        assert!(result.has_components());
        assert!(main.get_tool("ns/t1").is_some());
        assert!(main.get_resource("ns/file:///r1").is_some());
        assert!(main.get_prompt("ns/p1").is_some());
    }

    // ── mount resource conflict warnings ────────────────────────────────

    #[test]
    fn mount_warns_on_resource_conflict() {
        let mut main = Router::new();
        main.add_resource(NamedResource::new("file:///a"));
        let mut sub = Router::new();
        sub.add_resource(NamedResource::new("file:///a"));
        let result = main.mount(sub, None);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("Resource"));
    }

    #[test]
    fn mount_warns_on_prompt_conflict() {
        let mut main = Router::new();
        main.add_prompt(NamedPrompt::new("p"));
        let mut sub = Router::new();
        sub.add_prompt(NamedPrompt::new("p"));
        let result = main.mount(sub, None);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("Prompt"));
    }

    // ── TagFilters::clone ───────────────────────────────────────────────

    #[test]
    fn tag_filters_clone() {
        let include = vec!["a".to_string()];
        let f = TagFilters::new(Some(&include), None);
        let cloned = f.clone();
        assert!(cloned.matches(&["a".to_string()]));
        assert!(!cloned.matches(&["b".to_string()]));
    }

    // ── handle_tools_list with pagination AND tags ───────────────────────

    #[test]
    fn handle_tools_list_pagination_with_tags() {
        let mut r = Router::new();
        r.set_list_page_size(Some(1));
        r.add_tool(NamedTool::with_tags("a", vec!["db".to_string()]))
            .expect("tool registration succeeds");
        r.add_tool(NamedTool::with_tags("b", vec!["db".to_string()]))
            .expect("tool registration succeeds");
        r.add_tool(NamedTool::with_tags("c", vec!["web".to_string()]))
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let request_ctx = McpContext::new(cx, 1);

        // Only "db" tagged tools, page 1
        let params = ListToolsParams {
            cursor: None,
            include_tags: Some(vec!["db".to_string()]),
            exclude_tags: None,
        };
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "a");
        assert!(result.next_cursor.is_some());

        // Page 2
        let params = ListToolsParams {
            cursor: result.next_cursor,
            include_tags: Some(vec!["db".to_string()]),
            exclude_tags: None,
        };
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "b");
        assert!(result.next_cursor.is_none());
    }

    #[test]
    fn final_mounted_tools_preserve_admitted_order_before_cursor_pagination() {
        let mut router = mounted_tool_router();
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 164, Budget::INFINITE, &state);

        let legacy = router
            .handle_tools_list(
                &request_ctx,
                ListToolsParams {
                    cursor: None,
                    include_tags: Some(vec!["visible".to_owned()]),
                    exclude_tags: Some(vec!["excluded".to_owned()]),
                },
                None,
            )
            .expect("legacy filtering retains every registered tool");
        assert_eq!(
            legacy
                .tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            vec!["peer/first", "peer/second"],
            "the legacy catalog retains mounted tools in source order"
        );

        router.set_list_page_size(Some(1));
        let first_page = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_list_request(
                    None,
                    Some(vec!["visible"]),
                    Some(vec!["excluded"]),
                    164_i64,
                ),
            )
            .expect("the first final page contains the first admitted entry");
        assert_eq!(first_page["tools"][0]["name"], "peer/first");
        assert_eq!(first_page["tools"].as_array().map(Vec::len), Some(1));
        let cursor = first_page["nextCursor"]
            .as_str()
            .expect("the first admitted page has a continuation cursor");
        assert_eq!(
            decode_cursor_offset(Some(cursor)).expect("cursor is router-generated"),
            1,
            "the cursor advances across admitted entries"
        );

        let second_page = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_list_request(
                    Some(cursor),
                    Some(vec!["visible"]),
                    Some(vec!["excluded"]),
                    165_i64,
                ),
            )
            .expect("the continuation page keeps admitted source order");
        assert_eq!(second_page["tools"][0]["name"], "peer/second");
        assert_eq!(second_page["tools"].as_array().map(Vec::len), Some(1));
        assert!(
            second_page.get("nextCursor").is_none(),
            "the second admitted entry terminates the filtered final sequence"
        );
    }

    #[test]
    fn final_mounted_tools_apply_tag_filters_in_admitted_order() {
        let router = mounted_tool_router();
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 166, Budget::INFINITE, &state);

        let visible = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_list_request(None, Some(vec!["visible"]), None, 166_i64),
            )
            .expect("the final include filter projects only admitted visible entries");
        assert_eq!(
            visible["tools"]
                .as_array()
                .expect("final tools are an array")
                .iter()
                .map(|tool| tool["name"].as_str().expect("tool name is a string"))
                .collect::<Vec<_>>(),
            vec!["peer/first", "peer/second", "peer/excluded"],
            "tag filtering preserves admitted insertion order"
        );

        let other = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_list_request(None, Some(vec!["other"]), None, 167_i64),
            )
            .expect("the include filter is evaluated after final admission");
        assert_eq!(other["tools"][0]["name"], "peer/other");
        assert_eq!(other["tools"].as_array().map(Vec::len), Some(1));
    }

    // ── handle_resources_list with session state filter ──────────────────

    #[test]
    fn handle_resources_list_with_session_state_filter() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        r.add_resource(NamedResource::new("file:///b"));
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["file:///a".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_resources", &disabled);
        let params = ListResourcesParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let result = r
            .handle_resources_list(&request_ctx, params, Some(&state))
            .unwrap();
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.resources[0].uri, "file:///b");
    }

    // ── handle_prompts_list with session state filter ────────────────────

    #[test]
    fn handle_prompts_list_with_session_state_filter() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("a"));
        r.add_prompt(NamedPrompt::new("b"));
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> = ["a".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_prompts", &disabled);
        let params = ListPromptsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let result = r
            .handle_prompts_list(&request_ctx, params, Some(&state))
            .unwrap();
        assert_eq!(result.prompts.len(), 1);
        assert_eq!(result.prompts[0].name, "b");
    }

    // ── resource_templates_filtered by session + tags combined ───────────

    #[test]
    fn resource_templates_filtered_session_and_tags_combined() {
        let mut r = Router::new();
        r.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["admin".to_string()],
        });
        r.add_resource_template(ResourceTemplate {
            uri_template: "cache://{key}".to_string(),
            name: "cache".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["admin".to_string()],
        });
        r.add_resource_template(ResourceTemplate {
            uri_template: "log://{entry}".to_string(),
            name: "log".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec!["public".to_string()],
        });
        // Disable db template via session state
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["db://{table}".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_resources", &disabled);
        // Also filter by admin tag
        let include = vec!["admin".to_string()];
        let filters = TagFilters::new(Some(&include), None);
        let tmpls = r.resource_templates_filtered(Some(&state), Some(&filters));
        // db is disabled, log doesn't have admin tag => only cache
        assert_eq!(tmpls.len(), 1);
        assert_eq!(tmpls[0].name, "cache");
    }

    // ── mount_tools warns on template conflict ──────────────────────────

    #[test]
    fn mount_resource_template_warns_on_conflict() {
        let mut main = Router::new();
        main.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let mut sub = Router::new();
        sub.add_resource_template(ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "db2".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });
        let result = main.mount(sub, None);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("Resource template"));
    }

    // ── handle_tools_call: tool disabled via session ─────────────────────

    #[test]
    fn handle_tools_call_disabled_tool_returns_error() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("my_tool"))
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["my_tool".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_tools", &disabled);
        let params = CallToolParams {
            name: "my_tool".to_string(),
            arguments: None,
            meta: None,
        };
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_tools_call(&request_ctx, params, state, None, None)
            .unwrap_err();
        assert!(err.message.contains("disabled"));
    }

    // ── handle_tools_call: success path ──────────────────────────────────

    #[test]
    fn handle_tools_call_success() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("echo"))
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let params = CallToolParams {
            name: "echo".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let result = r
            .handle_tools_call(&request_ctx, params, state, None, None)
            .unwrap();
        assert!(!result.is_error);
        assert!(!result.content.is_empty());
    }

    // ── handle_tools_call: not found ─────────────────────────────────────

    #[test]
    fn handle_tools_call_not_found() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let params = CallToolParams {
            name: "missing".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_tools_call(&request_ctx, params, state, None, None)
            .unwrap_err();
        // The refusal deliberately does not echo the peer-controlled tool
        // name; only the sanitized method-not-found classification surfaces.
        assert_eq!(err.code, McpErrorCode::MethodNotFound);
        assert!(!err.message.contains("missing"));
    }

    // ── handle_tools_call: zero poll balance without poll admission ──────

    #[test]
    fn handle_tools_call_zero_poll_balance_allows_handler_without_checkpoint() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("t"))
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let budget = Budget::unlimited().with_poll_quota(0);
        let params = CallToolParams {
            name: "t".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let result = r
            .handle_tools_call(&request_ctx, params, state, None, None)
            .expect("a zero balance is not a retroactive failure");
        assert!(!result.is_error);
    }

    #[test]
    fn handle_tools_call_defers_pending_cancellation_inside_context_mask() {
        let mut router = Router::new();
        router
            .add_tool(NamedTool::new("t"))
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let params = || CallToolParams {
            name: "t".to_string(),
            arguments: None,
            meta: None,
        };

        let masked_result = request_ctx
            .masked(|| router.handle_tools_call(&request_ctx, params(), state.clone(), None, None))
            .expect("mask should be admitted");
        assert!(masked_result.is_ok());

        let unmasked_error = router
            .handle_tools_call(&request_ctx, params(), state, None, None)
            .expect_err("pending cancellation should surface after mask exit");
        assert_eq!(unmasked_error.code, McpErrorCode::RequestCancelled);
    }

    // ── handle_resources_read: resource disabled via session ──────────────

    #[test]
    fn handle_resources_read_disabled_resource_returns_error() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///secret"));
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["file:///secret".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_resources", &disabled);
        let params = ReadResourceParams {
            uri: "file:///secret".to_string(),
            meta: None,
        };
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_resources_read(&request_ctx, &params, state, None, None)
            .unwrap_err();
        assert!(err.message.contains("disabled"));
    }

    // ── handle_resources_read: success path ──────────────────────────────

    #[test]
    fn handle_resources_read_success() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let params = ReadResourceParams {
            uri: "file:///a".to_string(),
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let result = r
            .handle_resources_read(&request_ctx, &params, state, None, None)
            .unwrap();
        assert_eq!(result.contents.len(), 1);
        let [
            LegacyResourceContent::Text {
                uri,
                text,
                additional,
                ..
            },
        ] = result.contents.as_slice()
        else {
            panic!("resource read must retain the exact legacy text shape");
        };
        assert_eq!(uri, "file:///a");
        assert_eq!(text, "content");
        assert!(additional.is_empty());
    }

    // ── handle_resources_read: not found ─────────────────────────────────

    #[test]
    fn handle_resources_read_not_found() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let params = ReadResourceParams {
            uri: "file:///nonexistent".to_string(),
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_resources_read(&request_ctx, &params, state, None, None)
            .unwrap_err();
        assert!(err.message.contains("nonexistent") || err.message.contains("not found"));
    }

    // ── handle_resources_read: zero poll balance without admission ───────

    #[test]
    fn handle_resources_read_zero_poll_balance_allows_handler_without_checkpoint() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a"));
        let cx = Cx::for_testing();
        let budget = Budget::unlimited().with_poll_quota(0);
        let params = ReadResourceParams {
            uri: "file:///a".to_string(),
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let result = r
            .handle_resources_read(&request_ctx, &params, state, None, None)
            .expect("a zero balance is not a retroactive failure");
        assert_eq!(result.contents.len(), 1);
    }

    // ── handle_prompts_get: prompt disabled via session ───────────────────

    #[test]
    fn handle_prompts_get_disabled_prompt_returns_error() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("secret_prompt"));
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let state = SessionState::new();
        let disabled: std::collections::HashSet<String> =
            ["secret_prompt".to_string()].into_iter().collect();
        state.set("fastmcp.disabled_prompts", &disabled);
        let params = GetPromptParams {
            name: "secret_prompt".to_string(),
            arguments: None,
            meta: None,
        };
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_prompts_get(&request_ctx, params, state, None, None)
            .unwrap_err();
        assert!(err.message.contains("disabled"));
    }

    // ── handle_prompts_get: success path ─────────────────────────────────

    #[test]
    fn handle_prompts_get_success() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("greet"));
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let params = GetPromptParams {
            name: "greet".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let result = r
            .handle_prompts_get(&request_ctx, params, state, None, None)
            .unwrap();
        assert!(result.description.is_some());
    }

    // ── handle_prompts_get: not found ────────────────────────────────────

    #[test]
    fn handle_prompts_get_not_found() {
        let r = Router::new();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;
        let params = GetPromptParams {
            name: "missing".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_prompts_get(&request_ctx, params, state, None, None)
            .unwrap_err();
        assert!(err.message.contains("missing") || err.message.contains("not found"));
    }

    // ── handle_prompts_get: zero poll balance without admission ──────────

    #[test]
    fn handle_prompts_get_zero_poll_balance_allows_handler_without_checkpoint() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        let cx = Cx::for_testing();
        let budget = Budget::unlimited().with_poll_quota(0);
        let params = GetPromptParams {
            name: "p".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let result = r
            .handle_prompts_get(&request_ctx, params, state, None, None)
            .expect("a zero balance is not a retroactive failure");
        assert!(result.messages.is_empty());
    }

    #[test]
    fn handler_budget_composition_uses_exact_earliest_deadline() {
        let now = Time::from_secs(100);
        let at = |seconds| Budget::new().with_deadline(Time::from_secs(seconds));
        let cases = [
            (Budget::INFINITE, Budget::INFINITE, None, None),
            (at(110), Budget::INFINITE, None, Some(Time::from_secs(110))),
            (Budget::INFINITE, at(115), None, Some(Time::from_secs(115))),
            (
                at(110),
                at(115),
                Some(Duration::from_secs(30)),
                Some(Time::from_secs(110)),
            ),
            (
                at(140),
                at(130),
                Some(Duration::from_secs(5)),
                Some(Time::from_secs(105)),
            ),
            (
                at(110),
                at(115),
                Some(Duration::ZERO),
                Some(Time::from_secs(110)),
            ),
            (
                at(90),
                at(115),
                Some(Duration::from_secs(5)),
                Some(Time::from_secs(90)),
            ),
            (
                Budget::INFINITE,
                Budget::new().with_deadline(Time::from_nanos(u64::MAX - 1)),
                Some(Duration::MAX),
                Some(Time::from_nanos(u64::MAX - 1)),
            ),
        ];

        for (ambient, request, handler, expected) in cases {
            assert_eq!(
                compose_handler_budget(ambient, request, handler, now).deadline,
                expected
            );
        }
    }

    #[test]
    fn alternating_tool_resource_recursion_uses_one_effective_depth() {
        let calls = Arc::new(AtomicU64::new(0));
        let mut router = Router::new();
        router
            .add_tool(AlternatingTool {
                calls: Arc::clone(&calls),
            })
            .expect("tool registration succeeds");
        router.add_resource(AlternatingResource {
            calls: Arc::clone(&calls),
        });
        let router = Arc::new(router);
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = McpContext::with_state(cx, 1, state.clone())
            .with_tool_caller(Arc::new(RouterToolCaller::new(
                Arc::clone(&router),
                state.clone(),
            )))
            .with_resource_reader(Arc::new(RouterResourceReader::new(
                Arc::clone(&router),
                state.clone(),
            )));

        let error = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "alternating_tool".to_string(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect_err("alternating recursion must stop at the shared depth limit");

        assert_eq!(error.code, McpErrorCode::InternalError);
        assert!(error.message.contains("Maximum resource read depth"));
        assert_eq!(calls.load(Ordering::Relaxed), 11);
    }

    #[test]
    fn nested_tool_resource_call_shares_parent_cost_ledger() {
        let remaining_after_parent_debit = Arc::new(AtomicU64::new(u64::MAX));
        let remaining_after_nested_debit = Arc::new(AtomicU64::new(u64::MAX));
        let remaining_after_nested_read = Arc::new(AtomicU64::new(u64::MAX));
        let mut router = Router::new();
        router
            .add_tool(CostLedgerTool {
                remaining_after_parent_debit: Arc::clone(&remaining_after_parent_debit),
                remaining_after_nested_read: Arc::clone(&remaining_after_nested_read),
            })
            .expect("tool registration succeeds");
        router.add_resource(CostLedgerResource {
            remaining_after_nested_debit: Arc::clone(&remaining_after_nested_debit),
        });

        let router = Arc::new(router);
        let state = SessionState::new();
        let cx = Cx::for_testing_with_budget(Budget::new().with_cost_quota(3));
        let request_ctx = McpContext::with_state(cx, 77, state.clone())
            .with_tool_caller(Arc::new(RouterToolCaller::new(
                Arc::clone(&router),
                state.clone(),
            )))
            .with_resource_reader(Arc::new(RouterResourceReader::new(router, state)));

        let result = block_on(request_ctx.call_tool("cost_ledger_tool", serde_json::json!({})))
            .expect("parent and nested debits fit the shared cost quota");

        assert!(!result.is_error);
        assert_eq!(remaining_after_parent_debit.load(Ordering::Relaxed), 2);
        assert_eq!(remaining_after_nested_debit.load(Ordering::Relaxed), 1);
        assert_eq!(remaining_after_nested_read.load(Ordering::Relaxed), 1);
        assert_eq!(request_ctx.budget().cost_quota, Some(1));
    }

    #[test]
    fn nested_tool_calls_preserve_framework_terminal_errors() {
        let mut router = Router::new();
        router
            .add_tool(ErrorTool {
                name: "nested_cancelled",
                code: McpErrorCode::RequestCancelled,
            })
            .expect("tool registration succeeds");
        router
            .add_tool(ErrorTool {
                name: "nested_internal",
                code: McpErrorCode::InternalError,
            })
            .expect("tool registration succeeds");
        router
            .add_tool(ErrorTool {
                name: "nested_tool_failure",
                code: McpErrorCode::ToolExecutionError,
            })
            .expect("tool registration succeeds");
        let router = Arc::new(router);
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = McpContext::with_state(cx, 88, state.clone())
            .with_tool_caller(Arc::new(RouterToolCaller::new(Arc::clone(&router), state)));

        for (name, expected) in [
            ("nested_cancelled", McpErrorCode::RequestCancelled),
            ("nested_internal", McpErrorCode::InternalError),
        ] {
            let error = block_on(request_ctx.call_tool(name, serde_json::json!({})))
                .expect_err("framework terminal errors must remain outer failures");
            assert_eq!(error.code, expected);
        }

        let tool_failure =
            block_on(request_ctx.call_tool("nested_tool_failure", serde_json::json!({})))
                .expect("ordinary tool failures remain protocol-level tool results");
        assert!(tool_failure.is_error);
    }

    #[test]
    fn manual_handler_timeout_is_read_exposed_and_enforced() {
        let observed_deadline = Arc::new(Mutex::new(None));
        let timeout_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut router = Router::new();
        router
            .add_tool(BudgetProbeTool {
                timeout: Some(Duration::from_millis(1)),
                delay: Duration::from_millis(15),
                observed_deadline: Arc::clone(&observed_deadline),
                timeout_read: Arc::clone(&timeout_read),
            })
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let error = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "budget_probe".to_string(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect_err("the handler deadline must reject a late completion");

        assert!(timeout_read.load(Ordering::Relaxed));
        assert!(
            observed_deadline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some()
        );
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert_eq!(error.message, "Request timeout exceeded");
        assert!(!cx.is_cancel_requested());
    }

    #[test]
    fn admitted_definition_is_not_requeried_inside_handler_budget() {
        let definition_reads = Arc::new(AtomicU64::new(0));
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut router = Router::new();
        router
            .add_tool(SlowDefinitionTool {
                definition_reads: Arc::clone(&definition_reads),
                called: Arc::clone(&called),
            })
            .expect("the definition snapshot is admitted once");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);

        router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "slow_definition".to_string(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("dispatch uses the admitted snapshot and reaches the handler");

        assert!(called.load(Ordering::Relaxed));
        assert_eq!(definition_reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn zero_handler_timeout_cannot_relax_request_deadline() {
        let observed_deadline = Arc::new(Mutex::new(None));
        let timeout_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let request_deadline = wall_now().saturating_add_nanos(5_000_000_000);
        let mut router = Router::new();
        router
            .add_tool(BudgetProbeTool {
                timeout: Some(Duration::ZERO),
                delay: Duration::ZERO,
                observed_deadline: Arc::clone(&observed_deadline),
                timeout_read: Arc::clone(&timeout_read),
            })
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(
            &cx,
            1,
            Budget::new().with_deadline(request_deadline),
            &state,
        );
        router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "budget_probe".to_string(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("zero adds no ceiling but preserves the request deadline");

        assert!(timeout_read.load(Ordering::Relaxed));
        assert_eq!(
            *observed_deadline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(request_deadline)
        );
    }

    #[test]
    fn ambient_deadline_remains_visible_when_server_and_handler_are_looser() {
        let observed_deadline = Arc::new(Mutex::new(None));
        let timeout_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ambient_deadline = wall_now().saturating_add_nanos(2_000_000_000);
        let request_deadline = ambient_deadline.saturating_add_nanos(2_000_000_000);
        let mut router = Router::new();
        router
            .add_tool(BudgetProbeTool {
                timeout: Some(Duration::from_secs(10)),
                delay: Duration::ZERO,
                observed_deadline: Arc::clone(&observed_deadline),
                timeout_read,
            })
            .expect("tool registration succeeds");
        let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(ambient_deadline));
        let state = SessionState::new();
        let request_ctx = request_context(
            &cx,
            1,
            Budget::new().with_deadline(request_deadline),
            &state,
        );
        router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "budget_probe".to_string(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("looser inner limits must preserve the ambient deadline");

        assert_eq!(
            *observed_deadline
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(ambient_deadline)
        );
    }

    fn assert_sanitized_panic_tool(handler: impl ToolHandler + 'static, name: &str) {
        let mut router = Router::new();
        router
            .add_tool(handler)
            .expect("panic-test tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, Budget::INFINITE, &state);
        let error = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: name.to_string(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect_err("panic must terminate as a sanitized protocol error");
        let wire = serde_json::to_string(&error).expect("error serializes");
        assert_eq!(error.code, McpErrorCode::InternalError);
        assert_eq!(error.message, SANITIZED_HANDLER_PANIC_MESSAGE);
        assert_eq!(error.data, None);
        assert!(!wire.contains(PANIC_CANARY));
        assert!(!wire.contains("Bearer"));
        assert!(!wire.contains("secret"));
        assert!(!wire.contains("peer-secret"));
        assert!(!wire.contains("\u{001b}"));
        assert!(wire.len() < 256);
        assert!(!cx.is_cancel_requested());
    }

    #[test]
    fn unwinding_string_and_non_string_panics_have_one_fixed_peer_error() {
        assert_sanitized_panic_tool(
            UnwindingPanicTool {
                payload: "Bearer actual-secret".to_string(),
                non_string: false,
            },
            "panic_tool",
        );
        assert_sanitized_panic_tool(
            UnwindingPanicTool {
                payload: PANIC_CANARY.to_string(),
                non_string: true,
            },
            "panic_tool",
        );
    }

    #[test]
    fn four_valued_panic_payload_is_never_rendered_for_peer() {
        assert_sanitized_panic_tool(
            OutcomePanicTool(format!("{PANIC_CANARY}{}", "y".repeat(64 * 1024))),
            "outcome_panic_tool",
        );
    }

    #[test]
    fn opaque_internal_handler_errors_use_the_fixed_peer_contract() {
        let cx = Cx::for_testing();

        let mut tool_router = Router::new();
        tool_router
            .add_tool(OpaqueInternalTool)
            .expect("tool registration succeeds");
        let tool_state = SessionState::new();
        let tool_ctx = request_context(&cx, 1, Budget::INFINITE, &tool_state);
        let tool_error = tool_router
            .handle_tools_call(
                &tool_ctx,
                CallToolParams {
                    name: "opaque_internal_tool".to_string(),
                    arguments: None,
                    meta: None,
                },
                tool_state,
                None,
                None,
            )
            .expect_err("opaque internal tool errors must remain protocol failures");

        let mut resource_router = Router::new();
        resource_router.add_resource(OpaqueInternalResource);
        let resource_state = SessionState::new();
        let resource_ctx = request_context(&cx, 2, Budget::INFINITE, &resource_state);
        let resource_error = resource_router
            .handle_resources_read(
                &resource_ctx,
                &ReadResourceParams {
                    uri: "opaque://internal".to_string(),
                    meta: None,
                },
                resource_state,
                None,
                None,
            )
            .expect_err("opaque internal resource errors must be sanitized");

        let mut prompt_router = Router::new();
        prompt_router.add_prompt(OpaqueInternalPrompt);
        let prompt_state = SessionState::new();
        let prompt_ctx = request_context(&cx, 3, Budget::INFINITE, &prompt_state);
        let prompt_error = prompt_router
            .handle_prompts_get(
                &prompt_ctx,
                GetPromptParams {
                    name: "opaque_internal_prompt".to_string(),
                    arguments: None,
                    meta: None,
                },
                prompt_state,
                None,
                None,
            )
            .expect_err("opaque internal prompt errors must be sanitized");

        for error in [tool_error, resource_error, prompt_error] {
            let wire = serde_json::to_string(&error).expect("error serializes");
            assert_eq!(error.code, McpErrorCode::InternalError);
            assert_eq!(error.message, SANITIZED_HANDLER_PANIC_MESSAGE);
            assert_eq!(error.data, None);
            assert!(!wire.contains(PANIC_CANARY));
            assert!(wire.len() < 256);
        }
    }

    #[test]
    fn resource_and_prompt_panics_use_same_sanitized_contract() {
        let mut resource_router = Router::new();
        resource_router.add_resource(PanicResource);
        let resource_cx = Cx::for_testing();
        let resource_state = SessionState::new();
        let resource_ctx = request_context(&resource_cx, 1, Budget::INFINITE, &resource_state);
        let resource_error = resource_router
            .handle_resources_read(
                &resource_ctx,
                &ReadResourceParams {
                    uri: "panic://resource".to_string(),
                    meta: None,
                },
                resource_state,
                None,
                None,
            )
            .expect_err("resource panic must be sanitized");
        assert_eq!(resource_error.message, SANITIZED_HANDLER_PANIC_MESSAGE);

        let mut prompt_router = Router::new();
        prompt_router.add_prompt(PanicPrompt);
        let prompt_cx = Cx::for_testing();
        let prompt_state = SessionState::new();
        let prompt_ctx = request_context(&prompt_cx, 1, Budget::INFINITE, &prompt_state);
        let prompt_error = prompt_router
            .handle_prompts_get(
                &prompt_ctx,
                GetPromptParams {
                    name: "panic_prompt".to_string(),
                    arguments: None,
                    meta: None,
                },
                prompt_state,
                None,
                None,
            )
            .expect_err("prompt panic must be sanitized");
        assert_eq!(prompt_error.message, SANITIZED_HANDLER_PANIC_MESSAGE);

        for error in [resource_error, prompt_error] {
            let wire = serde_json::to_string(&error).expect("error serializes");
            assert!(!wire.contains(PANIC_CANARY));
            assert!(wire.len() < 256);
        }
    }

    #[test]
    fn admitted_tool_definition_is_snapshotted_while_other_list_panics_are_sanitized() {
        let cx = Cx::for_testing();
        let request_ctx = McpContext::new(cx, 1);

        let mut tool_router = Router::new();
        tool_router
            .add_tool(DefinitionPanicTool(std::sync::atomic::AtomicBool::new(
                false,
            )))
            .expect("the definition hook is read exactly once during admission");
        let tools = tool_router
            .handle_tools_list(&request_ctx, ListToolsParams::default(), None)
            .expect("listing clones the immutable admitted definition snapshot");
        assert_eq!(tools.tools.len(), 1);
        assert_eq!(tools.tools[0].name, "definition_panic_tool");

        let mut resource_router = Router::new();
        resource_router.add_resource(DefinitionPanicResource(std::sync::atomic::AtomicBool::new(
            false,
        )));
        let resource_error = resource_router
            .handle_resources_list(&request_ctx, ListResourcesParams::default(), None)
            .expect_err("resource definition panic must be sanitized");

        let mut prompt_router = Router::new();
        prompt_router.add_prompt(DefinitionPanicPrompt(std::sync::atomic::AtomicBool::new(
            false,
        )));
        let prompt_error = prompt_router
            .handle_prompts_list(&request_ctx, ListPromptsParams::default(), None)
            .expect_err("prompt definition panic must be sanitized");

        for error in [resource_error, prompt_error] {
            let wire = serde_json::to_string(&error).expect("error serializes");
            assert_eq!(error.code, McpErrorCode::InternalError);
            assert_eq!(error.message, SANITIZED_HANDLER_PANIC_MESSAGE);
            assert_eq!(error.data, None);
            assert!(!wire.contains(PANIC_CANARY));
            assert!(wire.len() < 256);
        }
    }

    // ── add_resource_with_behavior: template resource Error ───────────────

    #[test]
    fn add_resource_with_behavior_template_error_on_duplicate() {
        struct TmplResource;
        impl ResourceHandler for TmplResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "db://placeholder".to_string(),
                    name: "db".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }
            fn template(&self) -> Option<ResourceTemplate> {
                Some(ResourceTemplate {
                    uri_template: "db://{table}".to_string(),
                    name: "db".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                })
            }
            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![])
            }
        }
        let mut r = Router::new();
        r.add_resource(TmplResource);
        let err = r
            .add_resource_with_behavior(TmplResource, crate::DuplicateBehavior::Error)
            .unwrap_err();
        assert!(err.message.contains("already exists"));
    }

    // ── add_resource_with_behavior: template resource Ignore ─────────────

    #[test]
    fn add_resource_with_behavior_template_ignore_on_duplicate() {
        struct TmplResource2;
        impl ResourceHandler for TmplResource2 {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "cache://placeholder".to_string(),
                    name: "cache".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }
            fn template(&self) -> Option<ResourceTemplate> {
                Some(ResourceTemplate {
                    uri_template: "cache://{key}".to_string(),
                    name: "cache".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                })
            }
            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![])
            }
        }
        let mut r = Router::new();
        r.add_resource(TmplResource2);
        r.add_resource_with_behavior(TmplResource2, crate::DuplicateBehavior::Ignore)
            .unwrap();
        assert_eq!(r.resource_templates_count(), 1);
    }

    // ── add_resource_with_behavior: template resource Warn ───────────────

    #[test]
    fn add_resource_with_behavior_template_warn_on_duplicate() {
        struct TmplResource3;
        impl ResourceHandler for TmplResource3 {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "log://placeholder".to_string(),
                    name: "log".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }
            fn template(&self) -> Option<ResourceTemplate> {
                Some(ResourceTemplate {
                    uri_template: "log://{entry}".to_string(),
                    name: "log".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                })
            }
            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![])
            }
        }
        let mut r = Router::new();
        r.add_resource(TmplResource3);
        r.add_resource_with_behavior(TmplResource3, crate::DuplicateBehavior::Warn)
            .unwrap();
        assert_eq!(r.resource_templates_count(), 1);
    }

    // ── mount_tools warns on conflict ────────────────────────────────

    #[test]
    fn mount_tools_warns_on_tool_conflict() {
        let mut main = Router::new();
        main.add_tool(NamedTool::new("t"))
            .expect("tool registration succeeds");
        let mut sub = Router::new();
        sub.add_tool(NamedTool::new("t"))
            .expect("tool registration succeeds");
        let result = main.mount_tools(sub, None);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("Tool"));
    }

    // ── mount_prompts warns on conflict ──────────────────────────────────

    #[test]
    fn mount_prompts_warns_on_prompt_conflict() {
        let mut main = Router::new();
        main.add_prompt(NamedPrompt::new("p"));
        let mut sub = Router::new();
        sub.add_prompt(NamedPrompt::new("p"));
        let result = main.mount_prompts(sub, None);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("Prompt"));
    }

    // ── invalid cursor returns error ─────────────────────────────────────

    #[test]
    fn invalid_cursor_returns_error() {
        let mut r = Router::new();
        r.set_list_page_size(Some(1));
        r.add_tool(NamedTool::new("a"))
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let params = ListToolsParams {
            cursor: Some("not-valid-base64!!!".to_string()),
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let err = r.handle_tools_list(&request_ctx, params, None).unwrap_err();
        assert!(err.message.contains("cursor") || err.message.contains("Invalid"));
    }

    // ── set_list_page_size zero is treated as None ───────────────────────

    #[test]
    fn set_list_page_size_zero_disables_pagination() {
        let mut r = Router::new();
        r.set_list_page_size(Some(0));
        r.add_tool(NamedTool::new("a"))
            .expect("tool registration succeeds");
        r.add_tool(NamedTool::new("b"))
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let params = ListToolsParams {
            cursor: None,
            include_tags: None,
            exclude_tags: None,
        };
        let request_ctx = McpContext::new(cx, 1);
        let result = r.handle_tools_list(&request_ctx, params, None).unwrap();
        // With page_size = 0, all items returned (no pagination)
        assert_eq!(result.tools.len(), 2);
        assert!(result.next_cursor.is_none());
    }

    // ── strict_input_validation getter ───────────────────────────────────

    #[test]
    fn strict_input_validation_toggle() {
        let mut r = Router::new();
        assert!(!r.strict_input_validation());
        r.set_strict_input_validation(true);
        assert!(r.strict_input_validation());
        r.set_strict_input_validation(false);
        assert!(!r.strict_input_validation());
    }

    // ── cx-cancelled early return paths ──────────────────────────────────

    #[test]
    fn handle_tools_call_cancelled_cx_returns_error() {
        let mut r = Router::new();
        r.add_tool(NamedTool::new("t"))
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let budget = Budget::INFINITE;
        let params = CallToolParams {
            name: "t".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_tools_call(&request_ctx, params, state, None, None)
            .unwrap_err();
        assert_eq!(err.code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn handle_resources_read_cancelled_cx_returns_error() {
        let mut r = Router::new();
        r.add_resource(NamedResource::new("file:///a.txt"));
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let budget = Budget::INFINITE;
        let params = ReadResourceParams {
            uri: "file:///a.txt".to_string(),
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_resources_read(&request_ctx, &params, state, None, None)
            .unwrap_err();
        assert_eq!(err.code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn handle_prompts_get_cancelled_cx_returns_error() {
        let mut r = Router::new();
        r.add_prompt(NamedPrompt::new("p"));
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let budget = Budget::INFINITE;
        let params = GetPromptParams {
            name: "p".to_string(),
            arguments: None,
            meta: None,
        };
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 1, budget, &state);
        let err = r
            .handle_prompts_get(&request_ctx, params, state, None, None)
            .unwrap_err();
        assert_eq!(err.code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn completion_handler_dispatches_exact_legacy_and_final_contracts() {
        let mut router = Router::new();
        assert!(!router.has_completion_handler());
        router.add_completion_handler(EchoCompletion);
        router.add_prompt(NamedPrompt::new("deploy"));
        assert!(router.has_completion_handler());
        assert!(
            router
                .server_discovery_behavior_registry()
                .contains(ServerBehavior::CompletionComplete),
            "discovery advertises completion only after the handler is installed"
        );

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 87, Budget::INFINITE, &state);
        let legacy_request = JsonRpcRequest::new(
            COMPLETION_COMPLETE,
            Some(serde_json::json!({
                "ref": {"type": "ref/prompt", "name": "deploy"},
                "argument": {"name": "environment", "value": "sta"},
            })),
            87_i64,
        );
        let legacy = router
            .dispatch_legacy_completion(&request_ctx, &legacy_request)
            .expect("the exact legacy request reaches the registered completion handler");
        assert!(
            legacy.get("resultType").is_none(),
            "the exact legacy completion result remains discriminator-free"
        );
        assert_eq!(
            legacy["completion"]["values"],
            serde_json::json!(["staging"])
        );

        let modern = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    COMPLETION_COMPLETE,
                    Some(serde_json::json!({
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                        "ref": {"type": "ref/prompt", "name": "deploy"},
                        "argument": {"name": "environment", "value": "sta"},
                    })),
                    88_i64,
                ),
            )
            .expect("the final request reaches the same registered completion handler");
        assert_eq!(
            modern.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(modern.get("completion"), legacy.get("completion"));
    }

    #[test]
    fn explicit_legacy_completion_is_not_discovered_or_dispatched_as_final() {
        let mut router = Router::new();
        router.add_legacy_completion_handler(EchoCompletion);
        router.add_prompt(NamedPrompt::new("deploy"));
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 184, Budget::INFINITE, &state);
        let request = JsonRpcRequest::new(
            COMPLETION_COMPLETE,
            Some(serde_json::json!({
                "ref": {"type": "ref/prompt", "name": "deploy"},
                "argument": {"name": "environment", "value": "sta"},
            })),
            184_i64,
        );
        assert!(
            router
                .dispatch_legacy_completion(&request_ctx, &request)
                .is_ok()
        );

        let mut final_request = request.clone();
        final_request
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("completion parameters are an object")
            .insert(
                "_meta".to_owned(),
                serde_json::json!({
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                }),
            );
        let error = router
            .dispatch_stateless(&request_ctx, &final_request)
            .expect_err("only the selected protocol era changes completion availability");
        assert_eq!(error.code, McpErrorCode::MethodNotFound);
        assert!(
            !router
                .server_discovery_behavior_registry()
                .contains(ServerBehavior::CompletionComplete)
        );
    }

    #[test]
    fn final_completion_resource_reference_accepts_static_and_template_resources() {
        let mut router = Router::new();
        router.add_completion_handler(EchoCompletion);
        router.add_resource(NamedResource::new("resource://static"));
        router.add_resource_template(marked_template("resource://{id}", "registered"));
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 188, Budget::INFINITE, &state);
        let baseline = JsonRpcRequest::new(
            COMPLETION_COMPLETE,
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "ref": {"type": "ref/resource", "uri": "resource://{id}"},
                "argument": {"name": "id", "value": "sta"},
            })),
            188_i64,
        );
        let templates_before = serde_json::to_vec(&router.resource_templates())
            .expect("resource-template catalog serializes");
        let template_accepted = router
            .dispatch_stateless(&request_ctx, &baseline)
            .expect("a registered final resource-template reference is accepted");

        let mut static_reference = baseline.clone();
        static_reference
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|params| params.get_mut("ref"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("completion reference is an object")
            .insert("uri".to_owned(), serde_json::json!("resource://static"));
        let static_accepted = router
            .dispatch_stateless(&request_ctx, &static_reference)
            .expect("a registered final static resource reference is accepted");

        let mut planted = static_reference.clone();
        planted
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|params| params.get_mut("ref"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("completion reference is an object")
            .insert("uri".to_owned(), serde_json::json!("resource://missing"));
        let error = router
            .dispatch_stateless(&request_ctx, &planted)
            .expect_err("changing only the resource URI to an unregistered value is refused");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            serde_json::to_vec(&router.resource_templates())
                .expect("resource-template catalog serializes after refusal"),
            templates_before,
            "completion reference refusal cannot mutate the registered catalog"
        );
        assert_eq!(
            router
                .dispatch_stateless(&request_ctx, &baseline)
                .expect("the registered reference remains accepted after refusal"),
            template_accepted,
            "the planted URI is the only changed observable"
        );
        assert_eq!(
            router
                .dispatch_stateless(&request_ctx, &static_reference)
                .expect("the registered static resource remains accepted after refusal"),
            static_accepted,
            "the planted URI is the only changed observable"
        );
    }

    #[test]
    fn resource_template_registration_uses_the_protocol_rfc6570_matcher() {
        struct LevelFourTemplateResource;

        impl ResourceHandler for LevelFourTemplateResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "mcp://resource/template".to_owned(),
                    name: "level-four-template".to_owned(),
                    description: None,
                    mime_type: Some("text/plain".to_owned()),
                    icon: None,
                    version: None,
                    tags: Vec::new(),
                }
            }

            fn template(&self) -> Option<ResourceTemplate> {
                Some(marked_template(
                    "mcp://resource{/collection}/manifest{?revision}",
                    "level-four-template",
                ))
            }

            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                unreachable!("templated reads receive their URI parameters")
            }

            fn read_with_uri(
                &self,
                _ctx: &McpContext,
                uri: &str,
                params: &UriParams,
            ) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![ResourceContent {
                    uri: uri.to_owned(),
                    mime_type: Some("text/plain".to_owned()),
                    text: Some(format!(
                        "{}:{}",
                        params.get("collection").expect("collection is captured"),
                        params.get("revision").expect("revision is captured")
                    )),
                    blob: None,
                }])
            }
        }

        struct AmbiguousTemplateResource;

        impl ResourceHandler for AmbiguousTemplateResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "mcp://resource/ambiguous".to_owned(),
                    name: "ambiguous-template".to_owned(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: Vec::new(),
                }
            }

            fn template(&self) -> Option<ResourceTemplate> {
                Some(marked_template(
                    "mcp://resource/{first}{second}",
                    "ambiguous",
                ))
            }

            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                Ok(Vec::new())
            }
        }

        let mut router = Router::new();
        router
            .add_resource_with_behavior(
                LevelFourTemplateResource,
                crate::DuplicateBehavior::Replace,
            )
            .expect("a reversible level-four template is admitted");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 189, Budget::INFINITE, &state);
        let result = router
            .handle_resources_read(
                &request_ctx,
                &fastmcp_protocol::ReadResourceParams {
                    uri: "mcp://resource/books/manifest?revision=stable".to_owned(),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("the canonical matcher reaches the registered handler");
        let wire = serde_json::to_value(result).expect("resource result serializes");
        assert_eq!(wire["contents"][0]["text"], "books:stable");

        let template_count = router.resource_templates_count();
        let error = router
            .add_resource_with_behavior(
                AmbiguousTemplateResource,
                crate::DuplicateBehavior::Replace,
            )
            .expect_err("changing only the adjacent scalar boundary remains ambiguous");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            router.resource_templates_count(),
            template_count,
            "rejected template admission cannot mutate the registered catalog"
        );
    }

    #[test]
    fn completion_handler_rejects_one_field_final_metadata_in_legacy_request() {
        let mut router = Router::new();
        router.add_completion_handler(EchoCompletion);
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 89, Budget::INFINITE, &state);
        let baseline = JsonRpcRequest::new(
            COMPLETION_COMPLETE,
            Some(serde_json::json!({
                "ref": {"type": "ref/prompt", "name": "deploy"},
                "argument": {"name": "environment", "value": "sta"},
            })),
            89_i64,
        );
        let mut planted = baseline.clone();
        planted
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("completion parameters are an object")
            .insert(
                "_meta".to_string(),
                serde_json::json!({
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                }),
            );

        assert_eq!(baseline.method, planted.method);
        assert_eq!(baseline.id, planted.id);
        assert_eq!(
            baseline
                .params
                .as_ref()
                .and_then(|params| params.get("ref")),
            planted.params.as_ref().and_then(|params| params.get("ref")),
            "the final metadata object is the sole planted dimension"
        );
        let catalog_before = router.has_completion_handler();
        let planted_before = serde_json::to_vec(&planted).expect("planted request serializes");

        let baseline_result = router
            .dispatch_legacy_completion(&request_ctx, &baseline)
            .expect("the baseline legacy completion request is accepted");
        let error = router
            .dispatch_legacy_completion(&request_ctx, &planted)
            .expect_err("only final metadata is refused in the exact legacy request");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            serde_json::to_vec(&planted).expect("rejected request serializes"),
            planted_before,
            "cross-era rejection cannot mutate caller-owned completion parameters"
        );
        assert_eq!(
            router.has_completion_handler(),
            catalog_before,
            "cross-era rejection cannot alter the installed completion handler"
        );
        assert_eq!(
            router
                .dispatch_legacy_completion(&request_ctx, &baseline)
                .expect("the baseline remains accepted after the planted rejection"),
            baseline_result,
            "the one-field rejection cannot alter the accepted legacy completion result"
        );
    }

    #[test]
    fn macro_tool_dispatches_exact_legacy_and_final_complete_results() {
        let mut router = Router::new();
        MACRO_DUAL_ERA_TOOL_CALLS.store(0, Ordering::SeqCst);
        router
            .add_tool(MacroDualEraTool)
            .expect("macro tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 91, Budget::INFINITE, &state);

        let legacy = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "macro_dual_era_tool".to_string(),
                    arguments: Some(serde_json::json!({})),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("the legacy adapter still invokes the registered handler");
        let legacy_wire = serde_json::to_value(&legacy).expect("legacy result serializes");
        assert!(
            legacy_wire.get("resultType").is_none(),
            "the exact legacy result shape remains unchanged"
        );
        assert_eq!(legacy_wire["content"][0]["text"], "macro final tool result");

        let modern = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    "tools/call",
                    Some(serde_json::json!({
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                        "name": "macro_dual_era_tool",
                        "arguments": {},
                    })),
                    91_i64,
                ),
            )
            .expect("the modern router invokes the same installed handler");

        assert_eq!(
            modern.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(modern.get("content"), legacy_wire.get("content"));
        assert_eq!(modern.get("isError"), legacy_wire.get("isError"));
        assert!(modern.get("serverInfo").is_none());
        assert_eq!(
            modern["structuredContent"],
            serde_json::json!({"weather": "clear"})
        );
        assert_eq!(MACRO_DUAL_ERA_TOOL_CALLS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn final_tools_call_input_schema_failure_is_bounded_tool_error_without_handler_call() {
        let final_calls = Arc::new(AtomicUsize::new(0));
        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router
            .add_tool(SchemaBoundaryTool {
                final_calls: Arc::clone(&final_calls),
                legacy_calls: Arc::clone(&legacy_calls),
                output_matches_schema: true,
                output_is_error: false,
                output_has_unevaluated_property: false,
                invalid_final_input_schema: false,
                missing_final_input_object_type: false,
                invalid_final_output_schema: false,
            })
            .expect("schema-boundary tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 150, Budget::INFINITE, &state);

        let rejected = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "schema-boundary-tool",
                    serde_json::json!({"value": 7}),
                    150_i64,
                ),
            )
            .expect("registered final tool input failures are tool results");
        assert_eq!(rejected["resultType"], "complete");
        assert_eq!(rejected["isError"], true);
        assert_eq!(
            rejected["content"][0]["text"],
            "Tool arguments do not match the declared input schema."
        );
        assert_eq!(final_calls.load(Ordering::SeqCst), 0);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);

        let accepted = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "schema-boundary-tool",
                    serde_json::json!({"value": "accepted"}),
                    151_i64,
                ),
            )
            .expect("changing only the input value to match the schema is accepted");
        assert_eq!(accepted["resultType"], "complete");
        assert!(accepted.get("isError").is_none());
        assert_eq!(
            accepted["structuredContent"],
            serde_json::json!({"accepted": true})
        );
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn final_unknown_tool_is_invalid_params_while_legacy_unknown_tool_is_unchanged() {
        let router = Router::new();
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 152, Budget::INFINITE, &state);

        let modern_error = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request("unknown-tool", serde_json::json!({}), 152_i64),
            )
            .expect_err("an unknown final tool is an invalid-params protocol error");
        assert_eq!(modern_error.code, McpErrorCode::InvalidParams);

        let legacy_error = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "unknown-tool".to_owned(),
                    arguments: Some(serde_json::json!({})),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect_err("the exact legacy unknown-tool result remains method-not-found");
        assert_eq!(legacy_error.code, McpErrorCode::MethodNotFound);
    }

    #[test]
    fn final_tool_output_schema_is_checked_before_success_and_legacy_is_unchanged() {
        let final_calls = Arc::new(AtomicUsize::new(0));
        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router
            .add_tool(SchemaBoundaryTool {
                final_calls: Arc::clone(&final_calls),
                legacy_calls: Arc::clone(&legacy_calls),
                output_matches_schema: true,
                output_is_error: false,
                output_has_unevaluated_property: false,
                invalid_final_input_schema: false,
                missing_final_input_object_type: false,
                invalid_final_output_schema: false,
            })
            .expect("schema-boundary tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 153, Budget::INFINITE, &state);

        let accepted = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "schema-boundary-tool",
                    serde_json::json!({"value": "accepted"}),
                    153_i64,
                ),
            )
            .expect("a complete result matching the declared output schema is emitted");
        assert_eq!(
            accepted["structuredContent"],
            serde_json::json!({"accepted": true})
        );
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);

        let legacy = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "schema-boundary-tool".to_owned(),
                    arguments: Some(serde_json::json!({"value": "accepted"})),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("the legacy tool path does not apply final output-schema validation");
        assert!(!legacy.is_error);
        let legacy_wire = serde_json::to_value(&legacy).expect("legacy result serializes");
        assert_eq!(
            legacy_wire["content"][0]["text"],
            "legacy schema-boundary result"
        );
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 1);

        let rejected_final_calls = Arc::new(AtomicUsize::new(0));
        let rejected_legacy_calls = Arc::new(AtomicUsize::new(0));
        let mut rejected_router = Router::new();
        rejected_router
            .add_tool(SchemaBoundaryTool {
                final_calls: Arc::clone(&rejected_final_calls),
                legacy_calls: Arc::clone(&rejected_legacy_calls),
                output_matches_schema: false,
                output_is_error: false,
                output_has_unevaluated_property: false,
                invalid_final_input_schema: false,
                missing_final_input_object_type: false,
                invalid_final_output_schema: false,
            })
            .expect("schema-boundary tool registration succeeds");
        let rejected = rejected_router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "schema-boundary-tool",
                    serde_json::json!({"value": "accepted"}),
                    154_i64,
                ),
            )
            .expect_err("a complete result failing the declared output schema is not emitted");
        assert_eq!(rejected.code, McpErrorCode::InternalError);
        assert_eq!(
            rejected.message,
            "tool output does not match the declared output schema"
        );
        assert_eq!(rejected_final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(rejected_legacy_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn final_tool_output_schema_applies_to_complete_error_payloads() {
        let accepted_calls = Arc::new(AtomicUsize::new(0));
        let mut accepted_router = Router::new();
        accepted_router
            .add_tool(SchemaBoundaryTool {
                final_calls: Arc::clone(&accepted_calls),
                legacy_calls: Arc::new(AtomicUsize::new(0)),
                output_matches_schema: true,
                output_is_error: true,
                output_has_unevaluated_property: false,
                invalid_final_input_schema: false,
                missing_final_input_object_type: false,
                invalid_final_output_schema: false,
            })
            .expect("schema-boundary tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 154, Budget::INFINITE, &state);

        let accepted = accepted_router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "schema-boundary-tool",
                    serde_json::json!({"value": "accepted"}),
                    154_i64,
                ),
            )
            .expect("a schema-conforming complete error payload is emitted");
        assert_eq!(accepted["resultType"], "complete");
        assert_eq!(accepted["isError"], true);
        assert_eq!(
            accepted["structuredContent"],
            serde_json::json!({"accepted": true})
        );
        assert_eq!(accepted_calls.load(Ordering::SeqCst), 1);

        let rejected_calls = Arc::new(AtomicUsize::new(0));
        let mut rejected_router = Router::new();
        rejected_router
            .add_tool(SchemaBoundaryTool {
                final_calls: Arc::clone(&rejected_calls),
                legacy_calls: Arc::new(AtomicUsize::new(0)),
                output_matches_schema: false,
                output_is_error: true,
                output_has_unevaluated_property: false,
                invalid_final_input_schema: false,
                missing_final_input_object_type: false,
                invalid_final_output_schema: false,
            })
            .expect("schema-boundary tool registration succeeds");

        let rejected = rejected_router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "schema-boundary-tool",
                    serde_json::json!({"value": "accepted"}),
                    155_i64,
                ),
            )
            .expect_err("a nonconforming complete error payload is not emitted");
        assert_eq!(rejected.code, McpErrorCode::InternalError);
        assert_eq!(
            rejected.message,
            "tool output does not match the declared output schema"
        );
        assert_eq!(rejected_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn final_tool_admitted_schemas_enforce_unevaluated_properties_on_shipped_path() {
        let input_final_calls = Arc::new(AtomicUsize::new(0));
        let input_legacy_calls = Arc::new(AtomicUsize::new(0));
        let mut input_router = Router::new();
        input_router
            .add_tool(SchemaBoundaryTool {
                final_calls: Arc::clone(&input_final_calls),
                legacy_calls: Arc::clone(&input_legacy_calls),
                output_matches_schema: true,
                output_is_error: false,
                output_has_unevaluated_property: false,
                invalid_final_input_schema: false,
                missing_final_input_object_type: false,
                invalid_final_output_schema: false,
            })
            .expect("schema-boundary tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 155, Budget::INFINITE, &state);

        let rejected_input = input_router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "schema-boundary-tool",
                    serde_json::json!({"value": "accepted", "unexpected": true}),
                    155_i64,
                ),
            )
            .expect("unevaluated final input properties return the bounded tool error result");
        assert_eq!(rejected_input["resultType"], "complete");
        assert_eq!(rejected_input["isError"], true);
        assert_eq!(input_final_calls.load(Ordering::SeqCst), 0);
        assert_eq!(input_legacy_calls.load(Ordering::SeqCst), 0);

        let accepted_input = input_router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "schema-boundary-tool",
                    serde_json::json!({"value": "accepted"}),
                    156_i64,
                ),
            )
            .expect("removing only the unevaluated input property reaches the handler");
        assert_eq!(accepted_input["resultType"], "complete");
        assert_eq!(input_final_calls.load(Ordering::SeqCst), 1);

        let output_final_calls = Arc::new(AtomicUsize::new(0));
        let output_legacy_calls = Arc::new(AtomicUsize::new(0));
        let mut output_router = Router::new();
        output_router
            .add_tool(SchemaBoundaryTool {
                final_calls: Arc::clone(&output_final_calls),
                legacy_calls: Arc::clone(&output_legacy_calls),
                output_matches_schema: true,
                output_is_error: false,
                output_has_unevaluated_property: true,
                invalid_final_input_schema: false,
                missing_final_input_object_type: false,
                invalid_final_output_schema: false,
            })
            .expect("schema-boundary tool registration succeeds");

        let rejected_output = output_router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "schema-boundary-tool",
                    serde_json::json!({"value": "accepted"}),
                    157_i64,
                ),
            )
            .expect_err("an unevaluated final output property is not emitted as success");
        assert_eq!(rejected_output.code, McpErrorCode::InternalError);
        assert_eq!(
            rejected_output.message,
            "tool output does not match the declared output schema"
        );
        assert_eq!(output_final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(output_legacy_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn valid_final_tool_replace_updates_both_catalogs_without_reordering() {
        let original_legacy_calls = Arc::new(AtomicUsize::new(0));
        let original_final_calls = Arc::new(AtomicUsize::new(0));
        let replacement_legacy_calls = Arc::new(AtomicUsize::new(0));
        let replacement_final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router
            .add_tool(NamedTool::new("before"))
            .expect("tool registration succeeds");
        router
            .add_tool(AdmittedSchemaReplacementTool {
                legacy_calls: Arc::clone(&original_legacy_calls),
                final_calls: Arc::clone(&original_final_calls),
                legacy_label: "original",
                output_schema: serde_json::json!({"type": "string"}),
                structured_content: Some(serde_json::json!("original")),
            })
            .expect("original tool registration succeeds");
        router
            .add_tool(NamedTool::new("after"))
            .expect("tool registration succeeds");
        let order_before = router
            .tools()
            .into_iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>();

        router
            .add_tool_with_behavior(
                AdmittedSchemaReplacementTool {
                    legacy_calls: Arc::clone(&replacement_legacy_calls),
                    final_calls: Arc::clone(&replacement_final_calls),
                    legacy_label: "replacement",
                    output_schema: serde_json::json!({"type": "boolean"}),
                    structured_content: Some(serde_json::json!(true)),
                },
                crate::DuplicateBehavior::Replace,
            )
            .expect("a fully admitted replacement commits both catalog views");
        assert_eq!(
            router
                .tools()
                .into_iter()
                .map(|tool| tool.name)
                .collect::<Vec<_>>(),
            order_before,
            "replacement retains the original registration position"
        );

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 158, Budget::INFINITE, &state);
        let legacy = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "admitted-schema-replacement-tool".to_owned(),
                    arguments: Some(serde_json::json!({})),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("the replacement is installed for legacy dispatch");
        let legacy_wire = serde_json::to_value(&legacy).expect("legacy result serializes");
        assert_eq!(legacy_wire["content"][0]["text"], "replacement");
        assert_eq!(replacement_legacy_calls.load(Ordering::SeqCst), 1);
        assert_eq!(original_legacy_calls.load(Ordering::SeqCst), 0);

        let modern = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "admitted-schema-replacement-tool",
                    serde_json::json!({}),
                    159_i64,
                ),
            )
            .expect("the replacement is installed for modern dispatch");
        assert_eq!(modern["structuredContent"], serde_json::json!(true));
        assert_eq!(replacement_final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(original_final_calls.load(Ordering::SeqCst), 0);

        let modern_catalog = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_list_request(None, None, None, 160_i64),
            )
            .expect("the admitted replacement remains visible to the modern catalog");
        assert_eq!(
            modern_catalog["tools"]
                .as_array()
                .expect("modern tools remain an array")
                .iter()
                .map(|tool| tool["name"].as_str().expect("tool name is a string"))
                .collect::<Vec<_>>(),
            vec!["before", "admitted-schema-replacement-tool", "after"]
        );
        assert_eq!(
            modern_catalog["tools"][1]["outputSchema"]["type"],
            "boolean"
        );
    }

    #[test]
    fn invalid_final_schema_new_tool_leaves_both_catalogs_unchanged() {
        let mut router = Router::new();
        router
            .add_tool(NamedTool::new("existing"))
            .expect("baseline tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 161, Budget::INFINITE, &state);
        let legacy_before =
            serde_json::to_value(router.tools()).expect("legacy catalog serializes");
        let modern_before = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_list_request(None, None, None, 161_i64),
            )
            .expect("baseline modern catalog is available");

        let error = router
            .add_tool_with_behavior(
                InvalidFinalSchemaNamedTool::with_tags("new-invalid", Vec::new()),
                crate::DuplicateBehavior::Error,
            )
            .expect_err("a new normal tool with a scalar outputSchema is rejected");
        assert_eq!(error.code, McpErrorCode::InternalError);
        assert_eq!(
            serde_json::to_value(router.tools()).expect("legacy catalog serializes"),
            legacy_before,
            "failed admission cannot add a legacy-only entry"
        );
        assert_eq!(
            router
                .dispatch_stateless(
                    &request_ctx,
                    &final_tools_list_request(None, None, None, 162_i64),
                )
                .expect("modern catalog remains available"),
            modern_before,
            "failed admission cannot alter the modern catalog"
        );
        assert!(router.get_tool("new-invalid").is_none());
    }

    #[test]
    fn normal_registration_rejects_missing_input_schema_type_without_catalog_mutation() {
        let mut router = Router::new();
        router
            .add_tool(NamedTool::new("existing"))
            .expect("baseline tool registration succeeds");
        let legacy_before =
            serde_json::to_value(router.tools()).expect("legacy catalog serializes");

        let error = router
            .add_tool_with_behavior(
                SchemaBoundaryTool {
                    final_calls: Arc::new(AtomicUsize::new(0)),
                    legacy_calls: Arc::new(AtomicUsize::new(0)),
                    output_matches_schema: true,
                    output_is_error: false,
                    output_has_unevaluated_property: false,
                    invalid_final_input_schema: false,
                    missing_final_input_object_type: true,
                    invalid_final_output_schema: false,
                },
                crate::DuplicateBehavior::Error,
            )
            .expect_err("a normal inputSchema must declare type object");
        assert_eq!(error.code, McpErrorCode::InternalError);
        assert_eq!(
            serde_json::to_value(router.tools()).expect("legacy catalog serializes"),
            legacy_before
        );
        assert!(router.get_tool("schema-boundary-tool").is_none());
    }

    #[test]
    fn final_tool_scalar_and_null_structured_content_are_present_and_validated() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 163, Budget::INFINITE, &state);

        let mut scalar_router = Router::new();
        scalar_router
            .add_tool(AdmittedSchemaReplacementTool {
                legacy_calls: Arc::new(AtomicUsize::new(0)),
                final_calls: Arc::new(AtomicUsize::new(0)),
                legacy_label: "scalar",
                output_schema: serde_json::json!({"type": "string"}),
                structured_content: Some(serde_json::json!("")),
            })
            .expect("scalar-output tool registration succeeds");
        let scalar = scalar_router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "admitted-schema-replacement-tool",
                    serde_json::json!({}),
                    163_i64,
                ),
            )
            .expect("an object-valued schema document may describe a scalar result");
        assert_eq!(
            scalar.get("structuredContent"),
            Some(&serde_json::json!("")),
            "an empty string is present structured content, not an omitted value"
        );

        let mut null_router = Router::new();
        null_router
            .add_tool(AdmittedSchemaReplacementTool {
                legacy_calls: Arc::new(AtomicUsize::new(0)),
                final_calls: Arc::new(AtomicUsize::new(0)),
                legacy_label: "null",
                output_schema: serde_json::json!({"type": "null"}),
                structured_content: Some(serde_json::Value::Null),
            })
            .expect("null-output tool registration succeeds");
        let null = null_router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "admitted-schema-replacement-tool",
                    serde_json::json!({}),
                    164_i64,
                ),
            )
            .expect("present JSON null is validated against a null output schema");
        assert_eq!(
            null.get("structuredContent"),
            Some(&serde_json::Value::Null),
            "explicit JSON null remains present on the server-emission path"
        );
    }

    #[test]
    fn final_tool_declared_output_schema_rejects_absent_structured_content() {
        let mut router = Router::new();
        router
            .add_tool(AdmittedSchemaReplacementTool {
                legacy_calls: Arc::new(AtomicUsize::new(0)),
                final_calls: Arc::new(AtomicUsize::new(0)),
                legacy_label: "missing",
                output_schema: serde_json::json!({"type": "string"}),
                structured_content: None,
            })
            .expect("mapped tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 165, Budget::INFINITE, &state);

        let error = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "admitted-schema-replacement-tool",
                    serde_json::json!({}),
                    165_i64,
                ),
            )
            .expect_err("a declared output schema requires structured content on complete output");
        assert_eq!(error.code, McpErrorCode::InternalError);
        assert_eq!(
            error.message,
            "tool output is missing structuredContent required by the declared output schema"
        );
    }

    #[test]
    fn final_tool_error_mapper_covers_input_validation_and_handler_errors() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router
            .add_tool(ErrorMappedTool {
                mode: ErrorMapperMode::Complete,
                calls: Arc::clone(&calls),
            })
            .expect("both bounded mapper branches satisfy outputSchema");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 169, Budget::INFINITE, &state);

        let input_error = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "error-mapped-tool",
                    serde_json::json!({"value": 7}),
                    169_i64,
                ),
            )
            .expect("input rejection is a schema-valid complete tool error");
        assert_eq!(input_error["isError"], true);
        assert_eq!(
            input_error["structuredContent"],
            serde_json::json!({"error": "input-validation"})
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let handler_error = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "error-mapped-tool",
                    serde_json::json!({"value": "accepted"}),
                    170_i64,
                ),
            )
            .expect("handler rejection is a schema-valid complete tool error");
        assert_eq!(handler_error["isError"], true);
        assert_eq!(
            handler_error["structuredContent"],
            serde_json::json!({"error": "handler"})
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn incomplete_invalid_or_oversized_tool_error_mapper_is_rejected_atomically() {
        for (mode, expected_message) in [
            (
                ErrorMapperMode::MissingHandler,
                "tool declares outputSchema without a complete tool-error structured-content mapper",
            ),
            (
                ErrorMapperMode::InvalidHandler,
                "tool error structured-content mapper does not satisfy outputSchema",
            ),
            (
                ErrorMapperMode::OversizedHandler,
                "tool error structured-content mapper exceeded the registration limit",
            ),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut router = Router::new();
            router
                .add_tool(NamedTool::new("existing"))
                .expect("baseline tool admission succeeds");
            let cx = Cx::for_testing();
            let state = SessionState::new();
            let request_ctx = request_context(&cx, 171, Budget::INFINITE, &state);
            let legacy_before =
                serde_json::to_value(router.tools()).expect("legacy catalog serializes");
            let modern_before = router
                .dispatch_stateless(
                    &request_ctx,
                    &final_tools_list_request(None, None, None, 171_i64),
                )
                .expect("modern catalog is available");

            let error = router
                .add_tool(ErrorMappedTool {
                    mode,
                    calls: Arc::clone(&calls),
                })
                .expect_err("public add_tool exposes mapper admission failure");
            assert_eq!(error.code, McpErrorCode::InternalError);
            assert_eq!(error.message, expected_message);
            assert_eq!(
                serde_json::to_value(router.tools()).expect("legacy catalog serializes"),
                legacy_before
            );
            assert_eq!(
                router
                    .dispatch_stateless(
                        &request_ctx,
                        &final_tools_list_request(None, None, None, 172_i64),
                    )
                    .expect("modern catalog remains available"),
                modern_before
            );
            assert!(router.get_tool("error-mapped-tool").is_none());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn normal_registration_rejects_null_output_schema_without_catalog_mutation() {
        let mut router = Router::new();
        let error = router
            .add_tool_with_behavior(
                AdmittedSchemaReplacementTool {
                    legacy_calls: Arc::new(AtomicUsize::new(0)),
                    final_calls: Arc::new(AtomicUsize::new(0)),
                    legacy_label: "null-schema",
                    output_schema: serde_json::Value::Null,
                    structured_content: None,
                },
                crate::DuplicateBehavior::Error,
            )
            .expect_err("the outputSchema wire field itself must be an object");
        assert_eq!(error.code, McpErrorCode::InternalError);
        assert!(router.tools().is_empty());
        assert!(
            router
                .get_tool("admitted-schema-replacement-tool")
                .is_none()
        );
    }

    #[test]
    fn invalid_final_schema_replace_leaves_handlers_and_catalogs_unchanged() {
        let original_legacy_calls = Arc::new(AtomicUsize::new(0));
        let original_final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router
            .add_tool(AdmittedSchemaReplacementTool {
                legacy_calls: Arc::clone(&original_legacy_calls),
                final_calls: Arc::clone(&original_final_calls),
                legacy_label: "original",
                output_schema: serde_json::json!({"type": "string"}),
                structured_content: Some(serde_json::json!("original")),
            })
            .expect("original tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 166, Budget::INFINITE, &state);
        let legacy_before =
            serde_json::to_value(router.tools()).expect("legacy catalog serializes");
        let modern_before = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_list_request(None, None, None, 166_i64),
            )
            .expect("baseline modern catalog is available");

        let error = router
            .add_tool_with_behavior(
                InvalidFinalSchemaNamedTool::with_tags(
                    "admitted-schema-replacement-tool",
                    Vec::new(),
                ),
                crate::DuplicateBehavior::Replace,
            )
            .expect_err("changing only the candidate outputSchema rejects replacement");
        assert_eq!(error.code, McpErrorCode::InternalError);
        assert_eq!(
            serde_json::to_value(router.tools()).expect("legacy catalog serializes"),
            legacy_before,
            "a rejected replacement cannot replace the legacy handler"
        );
        assert_eq!(
            router
                .dispatch_stateless(
                    &request_ctx,
                    &final_tools_list_request(None, None, None, 167_i64),
                )
                .expect("modern catalog remains available"),
            modern_before,
            "a rejected replacement cannot remove the admitted modern entry"
        );

        let legacy = router
            .handle_tools_call(
                &request_ctx,
                CallToolParams {
                    name: "admitted-schema-replacement-tool".to_owned(),
                    arguments: Some(serde_json::json!({})),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("the original legacy handler remains installed");
        let legacy_wire = serde_json::to_value(&legacy).expect("legacy result serializes");
        assert_eq!(legacy_wire["content"][0]["text"], "original");
        assert_eq!(original_legacy_calls.load(Ordering::SeqCst), 1);

        let modern = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "admitted-schema-replacement-tool",
                    serde_json::json!({}),
                    168_i64,
                ),
            )
            .expect("the original modern handler remains installed");
        assert_eq!(modern["structuredContent"], serde_json::json!("original"));
        assert_eq!(original_final_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn final_tool_and_prompt_argument_nulls_are_rejected_without_erasing_absence() {
        let tool_final_calls = Arc::new(AtomicUsize::new(0));
        let prompt_final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router
            .add_tool(InputRequiredTool {
                legacy_calls: Arc::new(AtomicUsize::new(0)),
                final_calls: Arc::clone(&tool_final_calls),
            })
            .expect("tool registration succeeds");
        router.add_prompt(DirectFinalPrompt {
            final_calls: Arc::clone(&prompt_final_calls),
        });
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 160, Budget::INFINITE, &state);

        let absent_tool_arguments = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "name": "input-required-tool",
            })),
            160_i64,
        );
        let mut null_tool_arguments = absent_tool_arguments.clone();
        null_tool_arguments
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("final tool parameters are an object")
            .insert("arguments".to_owned(), serde_json::Value::Null);

        let CoreRequest::Final(FinalCoreRequest::ToolsCall(absent_tool_params)) =
            CoreRequest::decode(
                ProtocolEra::Modern2026,
                "tools/call",
                absent_tool_arguments.params.as_ref(),
            )
            .expect("absent final tool arguments decode")
        else {
            panic!("the final tool parameter shape is selected");
        };
        assert!(absent_tool_params.arguments.is_absent());
        let CoreRequest::Final(FinalCoreRequest::ToolsCall(null_tool_params)) =
            CoreRequest::decode(
                ProtocolEra::Modern2026,
                "tools/call",
                null_tool_arguments.params.as_ref(),
            )
            .expect("explicit-null final tool arguments decode")
        else {
            panic!("the final tool parameter shape is selected");
        };
        assert!(null_tool_params.arguments.is_explicit_null());

        let absent_tool_result = router
            .dispatch_stateless(&request_ctx, &absent_tool_arguments)
            .expect("absent final tool arguments default to an empty object");
        assert_eq!(absent_tool_result["resultType"], "input_required");
        assert_eq!(tool_final_calls.load(Ordering::SeqCst), 1);
        let null_tool_error = router
            .dispatch_stateless(&request_ctx, &null_tool_arguments)
            .expect_err("explicit-null final tool arguments are not defaulted");
        assert_eq!(null_tool_error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            null_tool_error.message,
            "tools/call arguments must not be null"
        );
        assert_eq!(tool_final_calls.load(Ordering::SeqCst), 1);

        let absent_prompt_arguments = direct_final_prompt_request(161_i64);
        let mut null_prompt_arguments = absent_prompt_arguments.clone();
        null_prompt_arguments
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("final prompt parameters are an object")
            .insert("arguments".to_owned(), serde_json::Value::Null);

        let CoreRequest::Final(FinalCoreRequest::PromptsGet(absent_prompt_params)) =
            CoreRequest::decode(
                ProtocolEra::Modern2026,
                "prompts/get",
                absent_prompt_arguments.params.as_ref(),
            )
            .expect("absent final prompt arguments decode")
        else {
            panic!("the final prompt parameter shape is selected");
        };
        assert!(absent_prompt_params.arguments.is_absent());
        let CoreRequest::Final(FinalCoreRequest::PromptsGet(null_prompt_params)) =
            CoreRequest::decode(
                ProtocolEra::Modern2026,
                "prompts/get",
                null_prompt_arguments.params.as_ref(),
            )
            .expect("explicit-null final prompt arguments decode")
        else {
            panic!("the final prompt parameter shape is selected");
        };
        assert!(null_prompt_params.arguments.is_explicit_null());

        let absent_prompt_result = router
            .dispatch_stateless(&request_ctx, &absent_prompt_arguments)
            .expect("absent final prompt arguments default to an empty map");
        assert_eq!(absent_prompt_result["resultType"], "complete");
        assert_eq!(prompt_final_calls.load(Ordering::SeqCst), 1);
        let null_prompt_error = router
            .dispatch_stateless(&request_ctx, &null_prompt_arguments)
            .expect_err("explicit-null final prompt arguments are not defaulted");
        assert_eq!(null_prompt_error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            null_prompt_error.message,
            "prompts/get arguments must not be null"
        );
        assert_eq!(prompt_final_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn final_task_capable_tool_creates_work_bound_task_after_capability_and_service_admission() {
        let final_calls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = task_runtime_for_router(Arc::clone(&store));
        let service_runner = runtime
            .install_task_service(1, Arc::new(NoopFinalTaskSupervisor))
            .expect("a bounded application-owned task service is installed");
        let service_cx = Cx::for_testing();
        let mut running_service = Box::pin(service_runner.run(&service_cx));
        let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Future::poll(running_service.as_mut(), &mut task_cx),
            Poll::Pending
        ));
        let mut router = Router::new();
        router.set_final_task_runtime(Some(runtime));
        router
            .add_tool(TaskCapableRouterTool {
                final_calls: Arc::clone(&final_calls),
            })
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 160, Budget::INFINITE, &state);

        let result = router
            .dispatch_stateless(&request_ctx, &final_task_capable_tool_request(160_i64))
            .expect("the admitted task-capable outcome creates a work-bound task");
        assert_eq!(result["resultType"], "task");
        assert_eq!(result["status"], "working");
        assert_eq!(result["statusMessage"], "router task created");
        assert!(
            result["taskId"].as_str().is_some(),
            "the created task has a final task identifier"
        );
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.task_count(), 1);
    }

    #[test]
    fn final_task_capable_tool_without_runtime_rejects_before_handler_without_store_mutation() {
        let final_calls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let mut router = Router::new();
        router
            .add_tool(TaskCapableRouterTool {
                final_calls: Arc::clone(&final_calls),
            })
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 161, Budget::INFINITE, &state);

        let error = router
            .dispatch_stateless(&request_ctx, &final_task_capable_tool_request(161_i64))
            .expect_err("a task-capable tool cannot run without a final Tasks runtime");
        assert_eq!(error.code, McpErrorCode::InternalError);
        assert_eq!(
            error.message,
            "task-capable tool requires an installed final Tasks runtime"
        );
        assert_eq!(final_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            store.task_count(),
            0,
            "pre-handler admission does not persist a task"
        );
    }

    #[test]
    fn final_task_capable_tool_with_unready_service_rejects_before_handler_without_store_mutation()
    {
        let final_calls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = task_runtime_for_router(Arc::clone(&store));
        let _unready_service = runtime
            .install_task_service(1, Arc::new(NoopFinalTaskSupervisor))
            .expect("an installed but unpolled task service remains unready");
        let mut router = Router::new();
        router.set_final_task_runtime(Some(runtime));
        router
            .add_tool(TaskCapableRouterTool {
                final_calls: Arc::clone(&final_calls),
            })
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 162, Budget::INFINITE, &state);

        let error = router
            .dispatch_stateless(&request_ctx, &final_task_capable_tool_request(162_i64))
            .expect_err("an installed but unready task service is refused before handler call");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            error.message,
            "Final task creation requires an installed ready task service"
        );
        assert_eq!(final_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            store.task_count(),
            0,
            "pre-handler readiness admission cannot persist a task"
        );
    }

    #[test]
    fn final_task_capable_tool_requires_peer_capability_before_handler() {
        let final_calls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = task_runtime_for_router(Arc::clone(&store));
        let service_runner = runtime
            .install_task_service(1, Arc::new(NoopFinalTaskSupervisor))
            .expect("a bounded application-owned task service is installed");
        let service_cx = Cx::for_testing();
        let mut running_service = Box::pin(service_runner.run(&service_cx));
        let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Future::poll(running_service.as_mut(), &mut task_cx),
            Poll::Pending
        ));
        let mut router = Router::new();
        router.set_final_task_runtime(Some(runtime));
        router
            .add_tool(TaskCapableRouterTool {
                final_calls: Arc::clone(&final_calls),
            })
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 162, Budget::INFINITE, &state);

        let error = router
            .dispatch_stateless(
                &request_ctx,
                &final_tools_call_request(
                    "task-capable-router-tool",
                    serde_json::json!({}),
                    162_i64,
                ),
            )
            .expect_err("a missing peer Tasks capability is refused before the handler runs");
        assert!(matches!(error.code, McpErrorCode::Custom(_)));
        assert_eq!(final_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.task_count(), 0);
    }

    #[test]
    fn final_router_defensively_rejects_an_undeclared_task_outcome() {
        let final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router
            .add_tool(UndeclaredTaskOutcomeRouterTool {
                final_calls: Arc::clone(&final_calls),
            })
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 163, Budget::INFINITE, &state);
        let request = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {
                        "extensions": {
                            "io.modelcontextprotocol/tasks": {}
                        }
                    },
                },
                "name": "undeclared-task-outcome-router-tool",
                "arguments": {},
            })),
            163_i64,
        );

        let error = router
            .dispatch_stateless(&request_ctx, &request)
            .expect_err("the router refuses a task outcome without a preflight declaration");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert_eq!(
            error.message,
            "tool returned CreateTask without declaring final Tasks capability"
        );
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn macro_tool_final_metadata_negative_is_non_mutating() {
        let mut router = Router::new();
        MACRO_DUAL_ERA_TOOL_CALLS.store(0, Ordering::SeqCst);
        router
            .add_tool(MacroDualEraTool)
            .expect("macro tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 92, Budget::INFINITE, &state);
        let baseline = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "name": "macro_dual_era_tool",
                "arguments": {},
            })),
            92_i64,
        );
        let mut planted = baseline.clone();
        planted
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("tools/call parameters are an object")
            .remove("_meta");

        assert_eq!(baseline.method, planted.method);
        assert_eq!(baseline.id, planted.id);
        assert_eq!(
            baseline
                .params
                .as_ref()
                .and_then(|params| params.get("name")),
            planted
                .params
                .as_ref()
                .and_then(|params| params.get("name")),
            "the final metadata object is the sole planted dimension"
        );
        let catalog_before = serde_json::to_vec(&router.tools()).expect("catalog serializes");
        let planted_before = serde_json::to_vec(&planted).expect("request serializes");

        let baseline_result = router
            .dispatch_stateless(&request_ctx, &baseline)
            .expect("the baseline invokes the registered handler");
        assert_eq!(
            baseline_result.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(MACRO_DUAL_ERA_TOOL_CALLS.load(Ordering::SeqCst), 1);

        let error = router
            .dispatch_stateless(&request_ctx, &planted)
            .expect_err("only final metadata is refused");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            serde_json::to_vec(&planted).expect("rejected request serializes"),
            planted_before,
            "typed refusal cannot mutate caller-owned input"
        );
        assert_eq!(
            serde_json::to_vec(&router.tools()).expect("catalog serializes"),
            catalog_before,
            "typed refusal cannot mutate the installed handler catalog"
        );
        assert_eq!(
            MACRO_DUAL_ERA_TOOL_CALLS.load(Ordering::SeqCst),
            1,
            "metadata refusal cannot invoke the macro-generated tool"
        );
        assert_eq!(
            router
                .dispatch_stateless(&request_ctx, &baseline)
                .expect("the unchanged baseline remains accepted after the rejection"),
            baseline_result,
            "the one-field rejection cannot alter the accepted final result"
        );
        assert_eq!(MACRO_DUAL_ERA_TOOL_CALLS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn public_final_dispatch_encodes_input_required_handler_outcomes() {
        let tool_legacy_calls = Arc::new(AtomicUsize::new(0));
        let tool_final_calls = Arc::new(AtomicUsize::new(0));
        let resource_legacy_calls = Arc::new(AtomicUsize::new(0));
        let resource_final_calls = Arc::new(AtomicUsize::new(0));
        let prompt_legacy_calls = Arc::new(AtomicUsize::new(0));
        let prompt_final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router
            .add_tool(InputRequiredTool {
                legacy_calls: Arc::clone(&tool_legacy_calls),
                final_calls: Arc::clone(&tool_final_calls),
            })
            .expect("tool registration succeeds");
        router.add_resource(InputRequiredResource {
            legacy_calls: Arc::clone(&resource_legacy_calls),
            final_calls: Arc::clone(&resource_final_calls),
        });
        router.add_prompt(InputRequiredPrompt {
            legacy_calls: Arc::clone(&prompt_legacy_calls),
            final_calls: Arc::clone(&prompt_final_calls),
        });

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 141, Budget::INFINITE, &state);
        let metadata = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        });

        let tool_request = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "_meta": metadata.clone(),
                "name": "input-required-tool",
                "arguments": {},
            })),
            141_i64,
        );
        let tool_typed = CoreRequest::decode(
            ProtocolEra::Modern2026,
            "tools/call",
            tool_request.params.as_ref(),
        )
        .expect("final tools/call request decodes");
        let tool_response = router
            .dispatch_stateless(&request_ctx, &tool_request)
            .expect("public final tools/call dispatch encodes input_required");
        assert_eq!(tool_response["resultType"], "input_required");
        assert_ne!(tool_response["requestState"], "tool-retry-state");
        assert_eq!(
            tool_response["inputRequests"]["roots"]["method"],
            "roots/list"
        );
        let tool_wire = serde_json::to_string(&tool_response).expect("tool response serializes");
        assert!(matches!(
            tool_typed.decode_result(&tool_wire),
            Ok(CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { result, .. }))
                if result.request_state().is_some()
        ));

        let resource_request = JsonRpcRequest::new(
            "resources/read",
            Some(serde_json::json!({
                "_meta": metadata.clone(),
                "uri": "file:///input-required-resource",
            })),
            142_i64,
        );
        let resource_typed = CoreRequest::decode(
            ProtocolEra::Modern2026,
            "resources/read",
            resource_request.params.as_ref(),
        )
        .expect("final resources/read request decodes");
        let resource_response = router
            .dispatch_stateless(&request_ctx, &resource_request)
            .expect("public final resources/read dispatch encodes input_required");
        assert_eq!(resource_response["resultType"], "input_required");
        assert_ne!(resource_response["requestState"], "resource-retry-state");
        assert_eq!(
            resource_response["inputRequests"]["roots"]["method"],
            "roots/list"
        );
        let resource_wire =
            serde_json::to_string(&resource_response).expect("resource response serializes");
        assert!(matches!(
            resource_typed.decode_result(&resource_wire),
            Ok(CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { result, .. }))
                if result.request_state().is_some()
        ));

        let prompt_request = JsonRpcRequest::new(
            "prompts/get",
            Some(serde_json::json!({
                "_meta": metadata,
                "name": "input-required-prompt",
            })),
            143_i64,
        );
        let prompt_typed = CoreRequest::decode(
            ProtocolEra::Modern2026,
            "prompts/get",
            prompt_request.params.as_ref(),
        )
        .expect("final prompts/get request decodes");
        let prompt_response = router
            .dispatch_stateless(&request_ctx, &prompt_request)
            .expect("public final prompts/get dispatch encodes input_required");
        assert_eq!(prompt_response["resultType"], "input_required");
        assert_ne!(prompt_response["requestState"], "prompt-retry-state");
        assert_eq!(
            prompt_response["inputRequests"]["roots"]["method"],
            "roots/list"
        );
        let prompt_wire =
            serde_json::to_string(&prompt_response).expect("prompt response serializes");
        assert!(matches!(
            prompt_typed.decode_result(&prompt_wire),
            Ok(CoreResult::Final(FinalCoreResult::PromptsGetInputRequired { result, .. }))
                if result.request_state().is_some()
        ));

        assert_eq!(tool_legacy_calls.load(Ordering::SeqCst), 0);
        assert_eq!(resource_legacy_calls.load(Ordering::SeqCst), 0);
        assert_eq!(prompt_legacy_calls.load(Ordering::SeqCst), 0);
        assert_eq!(tool_final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(resource_final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(prompt_final_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn modern_mrtr_retries_resume_each_method_once_and_refuse_replay_or_kind_mismatch() {
        let tool_final_calls = Arc::new(AtomicUsize::new(0));
        let resource_final_calls = Arc::new(AtomicUsize::new(0));
        let prompt_final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router
            .add_tool(InputRequiredTool {
                legacy_calls: Arc::new(AtomicUsize::new(0)),
                final_calls: Arc::clone(&tool_final_calls),
            })
            .expect("tool registration succeeds");
        router.add_resource(InputRequiredResource {
            legacy_calls: Arc::new(AtomicUsize::new(0)),
            final_calls: Arc::clone(&resource_final_calls),
        });
        router.add_prompt(InputRequiredPrompt {
            legacy_calls: Arc::new(AtomicUsize::new(0)),
            final_calls: Arc::clone(&prompt_final_calls),
        });

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 145, Budget::INFINITE, &state);
        let metadata = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        });

        let tool_initial = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "_meta": metadata.clone(),
                "name": "input-required-tool",
                "arguments": {},
            })),
            145_i64,
        );
        let tool_initial_result = router
            .dispatch_stateless(&request_ctx, &tool_initial)
            .expect("normal final dispatch mints the tool request state");
        let tool_state = tool_initial_result["requestState"]
            .as_str()
            .expect("framework result carries opaque tool state")
            .to_owned();
        let tool_retry = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "_meta": metadata.clone(),
                "name": "input-required-tool",
                "arguments": {},
                "inputResponses": {"roots": router_roots_response_wire()},
                "requestState": tool_state,
            })),
            145_i64,
        );
        let mut kind_mismatch = tool_retry.clone();
        kind_mismatch
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|params| params.get_mut("inputResponses"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("tool retry contains an inputResponses object")
            .insert(
                "roots".to_owned(),
                serde_json::to_value(
                    MrtrInputResponse::sampling(fastmcp_protocol::CreateMessageResult::text(
                        "not roots",
                        "test-model",
                    ))
                    .expect("sampling response serializes"),
                )
                .expect("sampling response converts to a wire value"),
            );
        let kind_error = router
            .dispatch_stateless(&request_ctx, &kind_mismatch)
            .expect_err("changing only the response kind is refused before handler invocation");
        assert_eq!(kind_error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            tool_final_calls.load(Ordering::SeqCst),
            1,
            "a wrong-kind retry must leave the matching state unconsumed"
        );

        let mut unknown_only = tool_retry.clone();
        *unknown_only
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|params| params.get_mut("inputResponses"))
            .expect("tool retry contains inputResponses") = serde_json::json!({"inert": null});
        let unknown_error = router
            .dispatch_stateless(&request_ctx, &unknown_only)
            .expect_err("unknown-only inputResponses cannot consume a tool continuation");
        assert_eq!(unknown_error.code, McpErrorCode::InvalidParams);
        assert_eq!(tool_final_calls.load(Ordering::SeqCst), 1);

        let mut oversized_map = tool_retry.clone();
        let responses = oversized_map
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|params| params.get_mut("inputResponses"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("tool retry contains an inputResponses object");
        for index in 0..crate::bidirectional::DEFAULT_MAX_MRTR_INPUT_REQUESTS_PER_ROUND {
            responses.insert(format!("inert-{index}"), serde_json::Value::Null);
        }
        let oversized_error = router
            .dispatch_stateless(&request_ctx, &oversized_map)
            .expect_err("an oversized raw response map is refused before retry decoding");
        assert_eq!(oversized_error.code, McpErrorCode::InvalidParams);
        assert_eq!(tool_final_calls.load(Ordering::SeqCst), 1);

        let mut tool_oversized_bytes = tool_retry.clone();
        tool_oversized_bytes
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|params| params.get_mut("inputResponses"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("tool retry contains an inputResponses object")
            .insert(
                "roots".to_owned(),
                serde_json::Value::String("x".repeat(MAX_MRTR_RAW_INPUT_RESPONSES_BYTES + 1)),
            );
        let tool_bytes_error = router
            .dispatch_stateless(&request_ctx, &tool_oversized_bytes)
            .expect_err("only an oversized tool response value is refused before retry decoding");
        assert_eq!(tool_bytes_error.code, McpErrorCode::InvalidParams);
        assert_eq!(tool_final_calls.load(Ordering::SeqCst), 1);

        let mut target_mismatch = tool_retry.clone();
        target_mismatch
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("tool retry parameters are an object")
            .insert("name".to_owned(), serde_json::json!("other-tool"));
        let target_error = router
            .dispatch_stateless(&request_ctx, &target_mismatch)
            .expect_err("changing only the target cannot consume a tool state");
        assert_eq!(target_error.code, McpErrorCode::InvalidParams);
        assert_eq!(tool_final_calls.load(Ordering::SeqCst), 1);

        let other_session = SessionState::new();
        let other_session_ctx = request_context(&cx, 145, Budget::INFINITE, &other_session);
        let session_error = router
            .dispatch_stateless(&other_session_ctx, &tool_retry)
            .expect_err("changing only the session cannot consume a tool state");
        assert_eq!(session_error.code, McpErrorCode::InvalidParams);
        assert_eq!(tool_final_calls.load(Ordering::SeqCst), 1);

        let principal_ctx = request_context(&cx, 145, Budget::INFINITE, &state);
        assert!(principal_ctx.set_auth(fastmcp_core::AuthContext::with_subject("other-user")));
        let principal_error = router
            .dispatch_stateless(&principal_ctx, &tool_retry)
            .expect_err("changing only the principal cannot consume a tool state");
        assert_eq!(principal_error.code, McpErrorCode::InvalidParams);
        assert_eq!(tool_final_calls.load(Ordering::SeqCst), 1);

        let tool_response = router
            .dispatch_stateless(&request_ctx, &tool_retry)
            .expect("a framework-minted tool state resumes through the final handler");
        assert_eq!(tool_response["resultType"], "input_required");
        assert_eq!(tool_final_calls.load(Ordering::SeqCst), 2);

        let resource_initial = JsonRpcRequest::new(
            "resources/read",
            Some(serde_json::json!({
                "_meta": metadata.clone(),
                "uri": "file:///input-required-resource",
            })),
            146_i64,
        );
        let resource_initial_result = router
            .dispatch_stateless(&request_ctx, &resource_initial)
            .expect("normal final dispatch mints the resource request state");
        let resource_state = resource_initial_result["requestState"]
            .as_str()
            .expect("framework result carries opaque resource state")
            .to_owned();
        let resource_retry = JsonRpcRequest::new(
            "resources/read",
            Some(serde_json::json!({
                "_meta": metadata.clone(),
                "uri": "file:///input-required-resource",
                "inputResponses": {"roots": router_roots_response_wire()},
                "requestState": resource_state,
            })),
            146_i64,
        );
        let mut resource_unknown_only = resource_retry.clone();
        *resource_unknown_only
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|params| params.get_mut("inputResponses"))
            .expect("resource retry contains inputResponses") = serde_json::json!({"inert": null});
        let resource_unknown_error = router
            .dispatch_stateless(&request_ctx, &resource_unknown_only)
            .expect_err("unknown-only inputResponses cannot consume a resource continuation");
        assert_eq!(resource_unknown_error.code, McpErrorCode::InvalidParams);
        assert_eq!(resource_final_calls.load(Ordering::SeqCst), 1);

        let mut resource_nested_value = serde_json::Value::Null;
        for _ in 0..=MAX_MRTR_RAW_JSON_DEPTH {
            resource_nested_value = serde_json::Value::Array(vec![resource_nested_value]);
        }
        let mut resource_oversized_depth = resource_retry.clone();
        resource_oversized_depth
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|params| params.get_mut("inputResponses"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("resource retry contains an inputResponses object")
            .insert("roots".to_owned(), resource_nested_value);
        let resource_depth_error = router
            .dispatch_stateless(&request_ctx, &resource_oversized_depth)
            .expect_err("only excessive response nesting is refused before retry decoding");
        assert_eq!(resource_depth_error.code, McpErrorCode::InvalidParams);
        assert_eq!(resource_final_calls.load(Ordering::SeqCst), 1);

        let resource_response = router
            .dispatch_stateless(&request_ctx, &resource_retry)
            .expect("a framework-minted resource state resumes through the final handler");
        assert_eq!(resource_response["resultType"], "input_required");
        assert_eq!(resource_final_calls.load(Ordering::SeqCst), 2);

        let prompt_initial = JsonRpcRequest::new(
            "prompts/get",
            Some(serde_json::json!({
                "_meta": metadata.clone(),
                "name": "input-required-prompt",
            })),
            147_i64,
        );
        let prompt_initial_result = router
            .dispatch_stateless(&request_ctx, &prompt_initial)
            .expect("normal final dispatch mints the prompt request state");
        let prompt_state = prompt_initial_result["requestState"]
            .as_str()
            .expect("framework result carries opaque prompt state")
            .to_owned();
        let prompt_retry = JsonRpcRequest::new(
            "prompts/get",
            Some(serde_json::json!({
                "_meta": metadata.clone(),
                "name": "input-required-prompt",
                "inputResponses": {"roots": router_roots_response_wire()},
                "requestState": prompt_state,
            })),
            147_i64,
        );
        let mut prompt_unknown_only = prompt_retry.clone();
        *prompt_unknown_only
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|params| params.get_mut("inputResponses"))
            .expect("prompt retry contains inputResponses") = serde_json::json!({"inert": null});
        let prompt_unknown_error = router
            .dispatch_stateless(&request_ctx, &prompt_unknown_only)
            .expect_err("unknown-only inputResponses cannot consume a prompt continuation");
        assert_eq!(prompt_unknown_error.code, McpErrorCode::InvalidParams);
        assert_eq!(prompt_final_calls.load(Ordering::SeqCst), 1);

        let mut prompt_oversized_values = prompt_retry.clone();
        prompt_oversized_values
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|params| params.get_mut("inputResponses"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("prompt retry contains an inputResponses object")
            .insert(
                "roots".to_owned(),
                serde_json::Value::Array(vec![serde_json::Value::Null; MAX_MRTR_RAW_JSON_VALUES]),
            );
        let prompt_values_error = router
            .dispatch_stateless(&request_ctx, &prompt_oversized_values)
            .expect_err(
                "only an oversized prompt response value set is refused before retry decoding",
            );
        assert_eq!(prompt_values_error.code, McpErrorCode::InvalidParams);
        assert_eq!(prompt_final_calls.load(Ordering::SeqCst), 1);

        let prompt_response = router
            .dispatch_stateless(&request_ctx, &prompt_retry)
            .expect("a framework-minted prompt state resumes through the final handler");
        assert_eq!(prompt_response["resultType"], "input_required");
        assert_eq!(prompt_final_calls.load(Ordering::SeqCst), 2);

        let replay = router
            .dispatch_stateless(&request_ctx, &tool_retry)
            .expect_err("replaying only the already consumed tool state is refused");
        assert_eq!(replay.code, McpErrorCode::InvalidParams);
        assert_eq!(
            tool_final_calls.load(Ordering::SeqCst),
            2,
            "replay must fail before the tool handler is invoked again"
        );
    }

    #[test]
    fn task_capability_metadata_rejection_preserves_the_mrtr_continuation() {
        let final_calls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = task_runtime_for_router(Arc::clone(&store));
        let service_runner = runtime
            .install_task_service(1, Arc::new(NoopFinalTaskSupervisor))
            .expect("a bounded application-owned task service is installed");
        let service_cx = Cx::for_testing();
        let mut running_service = Box::pin(service_runner.run(&service_cx));
        let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Future::poll(running_service.as_mut(), &mut task_cx),
            Poll::Pending
        ));

        let mut router = Router::new();
        router.set_final_task_runtime(Some(runtime));
        router
            .add_tool(TaskCapableInputRequiredTool {
                final_calls: Arc::clone(&final_calls),
            })
            .expect("task-capable input-required tool registration succeeds");
        let cx = Cx::for_testing();
        let session_state = SessionState::new();
        let request_ctx = request_context(&cx, 148, Budget::INFINITE, &session_state);
        let task_metadata = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            },
        });

        let initial = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "_meta": task_metadata.clone(),
                "name": "task-capable-input-required-tool",
                "arguments": {},
            })),
            148_i64,
        );
        let initial_result = router
            .dispatch_stateless(&request_ctx, &initial)
            .expect("task-capable tool mints an MRTR continuation after admission");
        let request_state = initial_result["requestState"]
            .as_str()
            .expect("framework result carries opaque task-capable state")
            .to_owned();
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);

        let retry = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "_meta": task_metadata,
                "name": "task-capable-input-required-tool",
                "arguments": {},
                "inputResponses": {"roots": router_roots_response_wire()},
                "requestState": request_state,
            })),
            149_i64,
        );
        let mut missing_task_capability = retry.clone();
        missing_task_capability
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("task-capability retry parameters are an object")
            .insert(
                "_meta".to_owned(),
                serde_json::json!({
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                }),
            );
        let capability_error = router
            .dispatch_stateless(&request_ctx, &missing_task_capability)
            .expect_err("altered Tasks capability is rejected before MRTR state consumption");
        assert!(matches!(capability_error.code, McpErrorCode::Custom(_)));
        assert_eq!(
            final_calls.load(Ordering::SeqCst),
            1,
            "the metadata rejection cannot invoke the resumed handler"
        );
        assert_eq!(store.task_count(), 0);

        let resumed = router
            .dispatch_stateless(&request_ctx, &retry)
            .expect("the original task-capable retry remains usable after rejection");
        assert_eq!(resumed["resultType"], "input_required");
        assert_eq!(final_calls.load(Ordering::SeqCst), 2);
        assert_eq!(store.task_count(), 0);
    }

    #[test]
    fn final_input_required_does_not_fallback_without_negotiation_metadata() {
        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router
            .add_tool(InputRequiredTool {
                legacy_calls: Arc::clone(&legacy_calls),
                final_calls: Arc::clone(&final_calls),
            })
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 144, Budget::INFINITE, &state);
        let baseline = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "name": "input-required-tool",
                "arguments": {},
            })),
            144_i64,
        );
        let mut planted = baseline.clone();
        planted
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("tools/call parameters are an object")
            .remove("_meta");

        assert_eq!(baseline.method, planted.method);
        assert_eq!(baseline.id, planted.id);
        assert_eq!(
            baseline
                .params
                .as_ref()
                .and_then(|params| params.get("name")),
            planted
                .params
                .as_ref()
                .and_then(|params| params.get("name")),
            "negotiation metadata is the sole planted dimension"
        );
        let catalog_before = serde_json::to_vec(&router.tools()).expect("catalog serializes");
        let planted_before = serde_json::to_vec(&planted).expect("request serializes");

        let accepted = router
            .dispatch_stateless(&request_ctx, &baseline)
            .expect("negotiated final request is accepted");
        assert_eq!(accepted["resultType"], "input_required");
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);

        let error = router
            .dispatch_stateless(&request_ctx, &planted)
            .expect_err("one-field no-negotiation request is rejected instead of falling back");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            serde_json::to_vec(&planted).expect("rejected request serializes"),
            planted_before,
            "rejection cannot mutate caller-owned no-negotiation parameters"
        );
        assert_eq!(
            serde_json::to_vec(&router.tools()).expect("catalog serializes"),
            catalog_before,
            "rejection cannot mutate the installed handler catalog"
        );
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
        let retried = router
            .dispatch_stateless(&request_ctx, &baseline)
            .expect("the negotiated baseline remains accepted after rejection");
        assert_eq!(retried["resultType"], "input_required");
        assert_ne!(
            retried["requestState"], accepted["requestState"],
            "every framework-issued MRTR continuation has fresh opaque state"
        );
        assert_eq!(final_calls.load(Ordering::SeqCst), 2);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn final_prompts_get_dispatches_direct_request_owned_handler() {
        let final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router.add_prompt(DirectFinalPrompt {
            final_calls: Arc::clone(&final_calls),
        });
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 96, Budget::INFINITE, &state);
        let request = direct_final_prompt_request(96);
        let typed_request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            "prompts/get",
            request.params.as_ref(),
        )
        .expect("final prompts/get request decodes through the public core surface");

        let response = router
            .dispatch_stateless(&request_ctx, &request)
            .expect("final prompts/get reaches the direct final handler");

        assert_eq!(
            response.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(
            response["description"],
            serde_json::json!("direct final prompt description")
        );
        assert_eq!(response["messages"][0]["content"]["type"], "audio");
        assert_eq!(
            response["messages"][0]["content"]["_meta"]["com.example/direct-prompt"]["source"],
            "final-handler"
        );
        assert_eq!(
            response["messages"][0]["content"]["com.example/direct-field"],
            true
        );
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);

        let wire = serde_json::to_string(&response).expect("final prompt response serializes");
        let CoreResult::Final(FinalCoreResult::PromptsGet { result, .. }) = typed_request
            .decode_result(&wire)
            .expect("final prompts/get result decodes through the public core surface")
        else {
            panic!("prompts/get selects the exact final result");
        };
        assert_eq!(
            result.payload.description.as_deref(),
            Some("direct final prompt description")
        );
        assert!(matches!(
            result.payload.messages.as_slice(),
            [FinalPromptMessage {
                content: ContentBlock::Audio { data, mime_type, .. },
                ..
            }] if data == "aGVsbG8=" && mime_type == "audio/mpeg"
        ));
    }

    #[test]
    fn final_prompt_arguments_are_validated_before_handler_and_legacy_is_unchanged() {
        let final_calls = Arc::new(AtomicUsize::new(0));
        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router.add_prompt(PromptArgumentBoundary {
            final_calls: Arc::clone(&final_calls),
            legacy_calls: Arc::clone(&legacy_calls),
        });
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 155, Budget::INFINITE, &state);
        let baseline = final_prompt_get_request(
            "prompt-argument-boundary",
            serde_json::json!({"topic": "release"}),
            155_i64,
        );
        let mut missing_required = baseline.clone();
        let removed_topic = missing_required
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|params| params.get_mut("arguments"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("prompt arguments are an object")
            .remove("topic");
        assert_eq!(removed_topic, Some(serde_json::json!("release")));

        assert_eq!(baseline.method, missing_required.method);
        assert_eq!(baseline.id, missing_required.id);
        assert_eq!(
            baseline
                .params
                .as_ref()
                .and_then(|params| params.get("_meta")),
            missing_required
                .params
                .as_ref()
                .and_then(|params| params.get("_meta")),
            "the required argument is the sole planted dimension"
        );
        assert_eq!(
            baseline
                .params
                .as_ref()
                .and_then(|params| params.get("name")),
            missing_required
                .params
                .as_ref()
                .and_then(|params| params.get("name")),
            "the required argument is the sole planted dimension"
        );

        let accepted = router
            .dispatch_stateless(&request_ctx, &baseline)
            .expect("the complete required-argument request is accepted");
        assert_eq!(accepted["resultType"], "complete");
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);

        let missing_error = router
            .dispatch_stateless(&request_ctx, &missing_required)
            .expect_err("removing only a required prompt argument is rejected");
        assert_eq!(missing_error.code, McpErrorCode::InvalidParams);
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);

        let unknown_error = router
            .dispatch_stateless(
                &request_ctx,
                &final_prompt_get_request("unknown-prompt", serde_json::json!({}), 156_i64),
            )
            .expect_err("an unknown final prompt is an invalid-params protocol error");
        assert_eq!(unknown_error.code, McpErrorCode::InvalidParams);
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);

        let legacy = router
            .handle_prompts_get(
                &request_ctx,
                GetPromptParams {
                    name: "prompt-argument-boundary".to_owned(),
                    arguments: None,
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect("the exact legacy prompt path retains its existing argument behavior");
        let legacy_wire = serde_json::to_value(&legacy).expect("legacy prompt result serializes");
        assert_eq!(
            legacy_wire["messages"][0]["content"]["text"],
            "legacy prompt-argument-boundary result"
        );
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn final_prompt_argument_snapshot_is_immutable_after_registration() {
        let expose_admitted_argument = Arc::new(AtomicBool::new(true));
        let final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router.add_prompt(MutablePromptDefinition {
            expose_admitted_argument: Arc::clone(&expose_admitted_argument),
            final_calls: Arc::clone(&final_calls),
        });
        expose_admitted_argument.store(false, Ordering::SeqCst);

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 156, Budget::INFINITE, &state);
        let accepted = final_prompt_get_request(
            "mutable-prompt-definition",
            serde_json::json!({"topic": "release"}),
            156_i64,
        );
        let mut missing_required = accepted.clone();
        let removed = missing_required
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|params| params.get_mut("arguments"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("prompt arguments are an object")
            .remove("topic");
        assert_eq!(removed, Some(serde_json::json!("release")));
        assert_eq!(accepted.method, missing_required.method);
        assert_eq!(accepted.id, missing_required.id);
        assert_eq!(
            accepted
                .params
                .as_ref()
                .and_then(|params| params.get("_meta")),
            missing_required
                .params
                .as_ref()
                .and_then(|params| params.get("_meta")),
            "the required argument is the sole planted dimension"
        );
        assert_eq!(
            accepted
                .params
                .as_ref()
                .and_then(|params| params.get("name")),
            missing_required
                .params
                .as_ref()
                .and_then(|params| params.get("name")),
            "the required argument is the sole planted dimension"
        );

        let catalog = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    "prompts/list",
                    Some(serde_json::json!({
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                    })),
                    157_i64,
                ),
            )
            .expect("the final prompt catalog retains its admitted argument metadata");
        assert_eq!(catalog["prompts"][0]["arguments"][0]["name"], "topic");
        assert_eq!(catalog["prompts"][0]["arguments"][0]["required"], true);

        let response = router
            .dispatch_stateless(&request_ctx, &accepted)
            .expect("the admitted final argument remains accepted after the legacy hook changes");
        assert_eq!(response["resultType"], "complete");
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);

        let error = router
            .dispatch_stateless(&request_ctx, &missing_required)
            .expect_err("removing only the admitted required argument is rejected");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn final_prompts_get_rejects_one_field_incompatible_result_type() {
        let final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router.add_prompt(DirectFinalPrompt {
            final_calls: Arc::clone(&final_calls),
        });
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 97, Budget::INFINITE, &state);
        let request = direct_final_prompt_request(97);
        let typed_request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            "prompts/get",
            request.params.as_ref(),
        )
        .expect("final prompts/get request decodes through the public core surface");
        let accepted = router
            .dispatch_stateless(&request_ctx, &request)
            .expect("the direct final prompt response is accepted");
        let accepted_wire = serde_json::to_string(&accepted).expect("accepted result serializes");
        let mut incompatible = accepted.clone();
        incompatible["resultType"] = serde_json::json!("input_required");

        let mut accepted_without_type = accepted.clone();
        let mut incompatible_without_type = incompatible.clone();
        let accepted_type = accepted_without_type
            .as_object_mut()
            .and_then(|object| object.remove("resultType"));
        let incompatible_type = incompatible_without_type
            .as_object_mut()
            .and_then(|object| object.remove("resultType"));
        assert_eq!(accepted_type, Some(serde_json::json!("complete")));
        assert_eq!(incompatible_type, Some(serde_json::json!("input_required")));
        assert_eq!(
            incompatible_without_type, accepted_without_type,
            "resultType is the sole incompatible result dimension"
        );

        let incompatible_wire =
            serde_json::to_string(&incompatible).expect("incompatible result serializes");
        assert!(matches!(
            typed_request.decode_result(&incompatible_wire),
            Err(fastmcp_protocol::CoreDispatchError::ResultCodec(_))
        ));
        assert_eq!(
            serde_json::to_string(&accepted).expect("accepted result remains serializable"),
            accepted_wire,
            "rejecting the one-field incompatible result cannot mutate the accepted response"
        );
        assert_eq!(
            final_calls.load(Ordering::SeqCst),
            1,
            "local result admission cannot invoke or mutate the direct prompt handler"
        );
        let reaccepted = typed_request
            .decode_result(&accepted_wire)
            .expect("the original direct final result remains accepted");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &reaccepted.encode().expect("reaccepted result encodes"),
            )
            .expect("reaccepted result is JSON"),
            accepted,
            "the incompatible result cannot alter the accepted final prompt contract"
        );
    }

    #[test]
    fn final_resources_read_dispatches_direct_handler_without_legacy_projection() {
        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router.add_resource(DirectFinalResource {
            legacy_calls: Arc::clone(&legacy_calls),
            final_calls: Arc::clone(&final_calls),
        });
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 98, Budget::INFINITE, &state);

        let legacy = router
            .handle_resources_read(
                &request_ctx,
                &ReadResourceParams {
                    uri: "file:///direct-final-resource".to_owned(),
                    meta: None,
                },
                state.clone(),
                None,
                None,
            )
            .expect("legacy resource requests retain their exact handler path");
        let [LegacyResourceContent::Text { text, .. }] = legacy.contents.as_slice() else {
            panic!("legacy resource result retains its exact text variant");
        };
        assert_eq!(text, "legacy resource result");
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 1);
        assert_eq!(final_calls.load(Ordering::SeqCst), 0);

        let request = direct_final_resource_request(98);
        let typed_request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            "resources/read",
            request.params.as_ref(),
        )
        .expect("final resources/read request decodes through the public core surface");
        let response = router
            .dispatch_stateless(&request_ctx, &request)
            .expect("final resources/read reaches the direct final handler");

        assert_eq!(response["resultType"], "complete");
        assert_eq!(response["ttlMs"], 321);
        assert_eq!(response["cacheScope"], "public");
        assert_eq!(
            response["contents"][0]["text"],
            "direct final resource result"
        );
        assert_eq!(response["contents"][0]["mimeType"], "text/markdown");
        assert_eq!(
            response["contents"][0]["_meta"]["com.example/direct-resource"]["source"],
            "final-handler"
        );
        assert_eq!(response["contents"][0]["com.example/direct-field"], true);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 1);
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);

        let wire = serde_json::to_string(&response).expect("final resource response serializes");
        let CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. }) = typed_request
            .decode_result(&wire)
            .expect("final resource result decodes through the public core surface")
        else {
            panic!("resources/read selects the exact final result");
        };
        assert_eq!(result.payload.ttl_ms, 321);
        assert_eq!(result.payload.cache_scope, CacheScope::Public);
        assert!(matches!(
            result.payload.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, mime_type, .. }]
                if text == "direct final resource result"
                    && mime_type.as_deref() == Some("text/markdown")
        ));
    }

    #[test]
    fn final_unknown_resource_is_invalid_params_with_exact_uri_and_legacy_is_unchanged() {
        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router.add_resource(DirectFinalResource {
            legacy_calls: Arc::clone(&legacy_calls),
            final_calls: Arc::clone(&final_calls),
        });
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 157, Budget::INFINITE, &state);
        let baseline = direct_final_resource_request(157);
        let mut unknown = baseline.clone();
        let replaced_uri = unknown
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("resource parameters are an object")
            .insert(
                "uri".to_owned(),
                serde_json::json!("file:///unknown-final-resource"),
            );
        assert_eq!(
            replaced_uri,
            Some(serde_json::json!("file:///direct-final-resource"))
        );

        assert_eq!(baseline.method, unknown.method);
        assert_eq!(baseline.id, unknown.id);
        assert_eq!(
            baseline
                .params
                .as_ref()
                .and_then(|params| params.get("_meta")),
            unknown
                .params
                .as_ref()
                .and_then(|params| params.get("_meta")),
            "the resource URI is the sole planted dimension"
        );

        let accepted = router
            .dispatch_stateless(&request_ctx, &baseline)
            .expect("the registered final resource is accepted");
        assert_eq!(accepted["resultType"], "complete");
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);

        let error = router
            .dispatch_stateless(&request_ctx, &unknown)
            .expect_err("changing only the URI to an unknown resource is rejected");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(error.message, "Resource not found");
        assert_eq!(
            error.data,
            Some(serde_json::json!({"uri": "file:///unknown-final-resource"}))
        );
        assert_eq!(final_calls.load(Ordering::SeqCst), 1);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);

        let legacy_error = router
            .handle_resources_read(
                &request_ctx,
                &ReadResourceParams {
                    uri: "file:///unknown-final-resource".to_owned(),
                    meta: None,
                },
                state,
                None,
                None,
            )
            .expect_err("the exact legacy missing-resource error remains unchanged");
        assert_eq!(legacy_error.code, McpErrorCode::ResourceNotFound);
        assert_eq!(
            legacy_error.message,
            "Resource not found: file:///unknown-final-resource"
        );
    }

    #[test]
    fn final_resources_read_rejects_one_field_incompatible_result_type() {
        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let final_calls = Arc::new(AtomicUsize::new(0));
        let mut router = Router::new();
        router.add_resource(DirectFinalResource {
            legacy_calls,
            final_calls: Arc::clone(&final_calls),
        });
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 99, Budget::INFINITE, &state);
        let request = direct_final_resource_request(99);
        let typed_request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            "resources/read",
            request.params.as_ref(),
        )
        .expect("final resources/read request decodes through the public core surface");
        let accepted = router
            .dispatch_stateless(&request_ctx, &request)
            .expect("the direct final resource response is accepted");
        let accepted_wire = serde_json::to_string(&accepted).expect("accepted result serializes");
        let mut incompatible = accepted.clone();
        incompatible["resultType"] = serde_json::json!("input_required");

        let mut accepted_without_type = accepted.clone();
        let mut incompatible_without_type = incompatible.clone();
        let accepted_type = accepted_without_type
            .as_object_mut()
            .and_then(|object| object.remove("resultType"));
        let incompatible_type = incompatible_without_type
            .as_object_mut()
            .and_then(|object| object.remove("resultType"));
        assert_eq!(accepted_type, Some(serde_json::json!("complete")));
        assert_eq!(incompatible_type, Some(serde_json::json!("input_required")));
        assert_eq!(
            incompatible_without_type, accepted_without_type,
            "resultType is the sole incompatible result dimension"
        );

        let incompatible_wire =
            serde_json::to_string(&incompatible).expect("incompatible result serializes");
        assert!(matches!(
            typed_request.decode_result(&incompatible_wire),
            Err(fastmcp_protocol::CoreDispatchError::ResultCodec(_))
        ));
        assert_eq!(
            serde_json::to_string(&accepted).expect("accepted result remains serializable"),
            accepted_wire,
            "rejecting the one-field incompatible result cannot mutate the accepted response"
        );
        assert_eq!(
            final_calls.load(Ordering::SeqCst),
            1,
            "local result admission cannot invoke or mutate the direct resource handler"
        );
        let reaccepted = typed_request
            .decode_result(&accepted_wire)
            .expect("the original direct final result remains accepted");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &reaccepted.encode().expect("reaccepted result encodes"),
            )
            .expect("reaccepted result is JSON"),
            accepted,
            "the incompatible result cannot alter the accepted final resource contract"
        );
    }

    #[test]
    fn final_catalog_preserves_resource_template_and_prompt_fields() {
        let resource_metadata = OpenMetadata::try_from_entries([(
            "com.example/resource".to_owned(),
            serde_json::json!({"source": "resource-handler"}),
        )])
        .expect("resource metadata is valid");
        let template_metadata = OpenMetadata::try_from_entries([(
            "com.example/template".to_owned(),
            serde_json::json!({"source": "template-handler"}),
        )])
        .expect("template metadata is valid");
        let prompt_metadata = OpenMetadata::try_from_entries([(
            "com.example/prompt".to_owned(),
            serde_json::json!({"source": "prompt-handler"}),
        )])
        .expect("prompt metadata is valid");
        let resource_annotations = Annotations {
            audience: None,
            priority: Some(0.25),
            last_modified: Some("2026-08-08T00:00:00Z".to_owned()),
            additional: BTreeMap::new(),
        };
        let template_annotations = Annotations {
            audience: None,
            priority: Some(0.75),
            last_modified: Some("2026-08-08T00:00:01Z".to_owned()),
            additional: BTreeMap::new(),
        };
        let resource_icon = RawIcon::try_with_details(
            "https://example.test/resource.png",
            Some("image/png".to_owned()),
            Some(vec!["32x32".to_owned()]),
            None,
        )
        .expect("resource icon is valid");
        let template_icon = RawIcon::try_with_details(
            "https://example.test/template.png",
            Some("image/png".to_owned()),
            Some(vec!["48x48".to_owned()]),
            None,
        )
        .expect("template icon is valid");
        let prompt_icon = RawIcon::try_with_details(
            "https://example.test/prompt.png",
            Some("image/png".to_owned()),
            Some(vec!["64x64".to_owned()]),
            None,
        )
        .expect("prompt icon is valid");

        let mut router = Router::new();
        router.add_resource(FinalCatalogResource {
            metadata: resource_metadata,
            icons: vec![resource_icon],
            annotations: resource_annotations,
        });
        router.add_resource(FinalCatalogResourceTemplate {
            metadata: template_metadata,
            icons: vec![template_icon],
            annotations: template_annotations,
        });
        router.add_prompt(FinalCatalogPrompt {
            metadata: prompt_metadata,
            icons: vec![prompt_icon],
        });

        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 96, Budget::INFINITE, &state);
        let final_metadata = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        });

        let resources = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    "resources/list",
                    Some(serde_json::json!({"_meta": final_metadata.clone()})),
                    96_i64,
                ),
            )
            .expect("final resource catalog is encoded");
        assert_eq!(resources["resources"][0]["title"], "Final Catalog Resource");
        assert_eq!(
            resources["resources"][0]["icons"][0]["src"],
            "https://example.test/resource.png"
        );
        assert_eq!(resources["resources"][0]["annotations"]["priority"], 0.25);
        assert_eq!(
            resources["resources"][0]["_meta"]["com.example/resource"]["source"],
            "resource-handler"
        );

        let templates = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    "resources/templates/list",
                    Some(serde_json::json!({"_meta": final_metadata.clone()})),
                    97_i64,
                ),
            )
            .expect("final resource-template catalog is encoded");
        assert_eq!(
            templates["resourceTemplates"][0]["title"],
            "Final Catalog Template"
        );
        assert_eq!(
            templates["resourceTemplates"][0]["icons"][0]["src"],
            "https://example.test/template.png"
        );
        assert_eq!(
            templates["resourceTemplates"][0]["annotations"]["priority"],
            0.75
        );
        assert_eq!(
            templates["resourceTemplates"][0]["_meta"]["com.example/template"]["source"],
            "template-handler"
        );

        let prompts = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new(
                    "prompts/list",
                    Some(serde_json::json!({"_meta": final_metadata})),
                    98_i64,
                ),
            )
            .expect("final prompt catalog is encoded");
        assert_eq!(prompts["prompts"][0]["title"], "Final Catalog Prompt");
        assert_eq!(
            prompts["prompts"][0]["icons"][0]["src"],
            "https://example.test/prompt.png"
        );
        assert_eq!(
            prompts["prompts"][0]["_meta"]["com.example/prompt"]["source"],
            "prompt-handler"
        );
        assert_eq!(prompts["prompts"][0]["arguments"][0]["required"], false);
    }

    #[test]
    fn final_resource_catalog_missing_metadata_is_non_mutating() {
        let metadata = OpenMetadata::try_from_entries([(
            "com.example/resource".to_owned(),
            serde_json::json!({"source": "resource-handler"}),
        )])
        .expect("resource metadata is valid");
        let icon = RawIcon::try_with_details(
            "https://example.test/resource.png",
            Some("image/png".to_owned()),
            None,
            None,
        )
        .expect("resource icon is valid");
        let mut router = Router::new();
        router.add_resource(FinalCatalogResource {
            metadata,
            icons: vec![icon],
            annotations: Annotations::default(),
        });
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 99, Budget::INFINITE, &state);
        let baseline = JsonRpcRequest::new(
            "resources/list",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            })),
            99_i64,
        );
        let mut planted = baseline.clone();
        planted
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("final resource-list parameters are an object")
            .remove("_meta");

        assert_eq!(baseline.method, planted.method);
        assert_eq!(baseline.id, planted.id);
        assert_eq!(
            baseline
                .params
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .map(serde_json::Map::len),
            Some(1),
            "the final metadata object is the sole baseline parameter"
        );
        assert_eq!(
            planted
                .params
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .map(serde_json::Map::len),
            Some(0),
            "the planted request differs only by final metadata removal"
        );
        let catalog_before = serde_json::to_vec(&router.resources()).expect("catalog serializes");
        let planted_before = serde_json::to_vec(&planted).expect("request serializes");
        let baseline_result = router
            .dispatch_stateless(&request_ctx, &baseline)
            .expect("final baseline is accepted");
        assert_eq!(
            baseline_result["resources"][0]["title"],
            "Final Catalog Resource"
        );

        let error = router
            .dispatch_stateless(&request_ctx, &planted)
            .expect_err("only final request metadata is refused");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            serde_json::to_vec(&planted).expect("rejected request serializes"),
            planted_before,
            "the one-field rejection cannot mutate caller-owned input"
        );
        assert_eq!(
            serde_json::to_vec(&router.resources()).expect("catalog serializes"),
            catalog_before,
            "the one-field rejection cannot mutate the resource catalog"
        );
        assert_eq!(
            router
                .dispatch_stateless(&request_ctx, &baseline)
                .expect("the baseline remains accepted after rejection"),
            baseline_result,
            "the one-field rejection cannot alter final field preservation"
        );
    }

    #[test]
    fn core_request_decode_result_round_trips_final_catalog_and_read_cache_hints() {
        let metadata = OpenMetadata::try_from_entries([(
            "com.example/catalog".to_owned(),
            serde_json::json!({"source": "handler"}),
        )])
        .expect("valid final catalog metadata");
        let icon = RawIcon::try_with_details(
            "https://example.test/tool.png",
            Some("image/png".to_owned()),
            Some(vec!["48x48".to_owned()]),
            None,
        )
        .expect("valid final icon");
        let alternate_icon = RawIcon::try_with_details(
            "https://example.test/tool-dark.svg",
            Some("image/svg+xml".to_owned()),
            Some(vec!["any".to_owned()]),
            Some(fastmcp_protocol::common_types::IconTheme::Dark),
        )
        .expect("valid alternate final icon");
        let mut router = Router::new();
        router.set_final_cache_hint_policy(123, 456, CacheScope::Private);
        router
            .add_tool(FinalCatalogTool {
                metadata,
                icons: vec![icon, alternate_icon],
            })
            .expect("final catalog tool registration succeeds");
        router.add_resource(NamedResource::new("file:///catalog-resource"));
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 93, Budget::INFINITE, &state);

        let legacy = router
            .handle_tools_list(&request_ctx, ListToolsParams::default(), None)
            .expect("legacy catalog remains available");
        let legacy_wire = serde_json::to_value(&legacy).expect("legacy catalog serializes");
        assert!(legacy_wire.get("ttlMs").is_none());
        assert!(legacy_wire.get("cacheScope").is_none());
        assert!(legacy_wire["tools"][0].get("icon").is_some());
        assert!(legacy_wire["tools"][0].get("version").is_some());
        assert!(legacy_wire["tools"][0].get("tags").is_some());

        let final_list_params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        });
        let final_list_request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            "tools/list",
            Some(&final_list_params),
        )
        .expect("final catalog request decodes through the public core surface");
        let modern_list = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new("tools/list", Some(final_list_params), 93_i64),
            )
            .expect("final catalog is projected through the exact model");
        assert_eq!(modern_list["resultType"], "complete");
        assert_eq!(modern_list["ttlMs"], 123);
        assert_eq!(modern_list["cacheScope"], "private");
        assert_eq!(modern_list["tools"][0]["title"], "Exact Final Catalog Tool");
        assert_eq!(
            modern_list["tools"][0]["annotations"]["title"],
            "Exact annotation title"
        );
        assert_eq!(
            modern_list["tools"][0]["icons"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            modern_list["tools"][0]["icons"][0]["sizes"],
            serde_json::json!(["48x48"])
        );
        assert_eq!(
            modern_list["tools"][0]["_meta"]["com.example/catalog"]["source"],
            "handler"
        );
        assert_eq!(modern_list["tools"][0]["outputSchema"]["type"], "object");
        assert!(modern_list["tools"][0].get("icon").is_none());
        assert!(modern_list["tools"][0].get("version").is_none());
        assert!(modern_list["tools"][0].get("tags").is_none());
        let modern_list_wire =
            serde_json::to_string(&modern_list).expect("final catalog response serializes");
        let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = final_list_request
            .decode_result(&modern_list_wire)
            .expect("final catalog response decodes through the public core surface")
        else {
            panic!("tools/list selects the exact final catalog result");
        };
        assert_eq!(result.payload.ttl_ms, 123);
        assert_eq!(result.payload.cache_scope, CacheScope::Private);
        let final_tool = result
            .payload
            .tools
            .first()
            .expect("final catalog contains the registered tool");
        assert_eq!(
            final_tool.title.as_deref(),
            Some("Exact Final Catalog Tool")
        );
        assert_eq!(
            final_tool
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.title.as_deref()),
            Some("Exact annotation title")
        );
        assert_eq!(final_tool.icons.as_ref().map(Vec::len), Some(2));
        assert_eq!(
            final_tool
                .icons
                .as_ref()
                .and_then(|icons| icons.first())
                .map(|icon| icon.src.as_str()),
            Some("https://example.test/tool.png")
        );
        assert_eq!(
            final_tool
                .meta
                .as_ref()
                .and_then(|metadata| metadata.get("com.example/catalog"))
                .and_then(|value| value.get("source"))
                .and_then(serde_json::Value::as_str),
            Some("handler")
        );
        assert_eq!(
            final_tool
                .output_schema
                .as_ref()
                .and_then(|schema| schema.get("type"))
                .and_then(serde_json::Value::as_str),
            Some("object")
        );

        let final_read_params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
            "uri": "file:///catalog-resource",
        });
        let final_read_request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            "resources/read",
            Some(&final_read_params),
        )
        .expect("final resource-read request decodes through the public core surface");
        let modern_read = router
            .dispatch_stateless(
                &request_ctx,
                &JsonRpcRequest::new("resources/read", Some(final_read_params), 94_i64),
            )
            .expect("final resource content is projected through the final model");
        assert_eq!(modern_read["ttlMs"], 456);
        assert_eq!(modern_read["cacheScope"], "private");
        assert_eq!(
            modern_read["contents"][0]["uri"],
            "file:///catalog-resource"
        );
        assert_eq!(modern_read["contents"][0]["text"], "content");
        let modern_read_wire =
            serde_json::to_string(&modern_read).expect("final resource-read response serializes");
        let CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. }) = final_read_request
            .decode_result(&modern_read_wire)
            .expect("final resource-read response decodes through the public core surface")
        else {
            panic!("resources/read selects the exact final read result");
        };
        assert_eq!(result.payload.ttl_ms, 456);
        assert_eq!(result.payload.cache_scope, CacheScope::Private);
        assert!(matches!(
            result.payload.contents.as_slice(),
            [EmbeddedResourceContents::Text { text, .. }] if text == "content"
        ));
    }

    #[test]
    fn final_catalog_missing_metadata_is_non_mutating() {
        let mut router = Router::new();
        router
            .add_tool(NamedTool::new("metadata-guarded-tool"))
            .expect("tool registration succeeds");
        let cx = Cx::for_testing();
        let state = SessionState::new();
        let request_ctx = request_context(&cx, 95, Budget::INFINITE, &state);
        let baseline = JsonRpcRequest::new(
            "tools/list",
            Some(serde_json::json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            })),
            95_i64,
        );
        let mut planted = baseline.clone();
        planted
            .params
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .expect("final list parameters are an object")
            .remove("_meta");
        assert_eq!(baseline.method, planted.method);
        assert_eq!(baseline.id, planted.id);
        let catalog_before = serde_json::to_vec(&router.tools()).expect("catalog serializes");
        let planted_before = serde_json::to_vec(&planted).expect("request serializes");

        let baseline_result = router
            .dispatch_stateless(&request_ctx, &baseline)
            .expect("the final baseline is accepted");
        let error = router
            .dispatch_stateless(&request_ctx, &planted)
            .expect_err("only missing final metadata is refused");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            serde_json::to_vec(&planted).expect("rejected request serializes"),
            planted_before,
            "the rejected one-field request remains unchanged"
        );
        assert_eq!(
            serde_json::to_vec(&router.tools()).expect("catalog serializes"),
            catalog_before,
            "the rejected one-field request cannot mutate the catalog"
        );
        assert_eq!(
            router
                .dispatch_stateless(&request_ctx, &baseline)
                .expect("the unchanged final baseline remains accepted"),
            baseline_result,
            "the rejection cannot alter final cache hints or catalog projection"
        );
    }

    #[test]
    fn srv_04_modern_owned_dispatch_runs_requests_concurrently() {
        let started = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(Mutex::new(Vec::new()));
        let mut router = Router::new();
        router
            .add_tool(ConcurrentModernTool::new(
                Arc::clone(&started),
                Arc::clone(&completed),
            ))
            .expect("tool registration succeeds");
        let router = Arc::new(router);
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("the test runtime is available");
        let runtime_handle = runtime.handle();
        let mut first = spawn_owned_modern_request(
            &runtime_handle,
            Arc::clone(&router),
            401,
            "modern-one",
            "one",
            None,
        );
        let mut second =
            spawn_owned_modern_request(&runtime_handle, router, 402, "modern-two", "two", None);

        let (first, second) = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs an observer context");
            let first = first
                .recv(&cx)
                .await
                .expect("the first owner reports a terminal result");
            let second = second
                .recv(&cx)
                .await
                .expect("the second owner reports a terminal result");
            (first, second)
        });
        let first = first.expect("the first modern request completes");
        let second = second.expect("the second modern request completes");

        assert_eq!(started.load(Ordering::SeqCst), 2);
        assert_eq!(
            first.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(
            second.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        let mut completed = completed
            .lock()
            .expect("completion probe lock is not poisoned")
            .clone();
        completed.sort();
        assert_eq!(completed, vec!["one".to_string(), "two".to_string()]);
    }

    #[test]
    fn srv_04_modern_owned_cancellation_does_not_change_sibling() {
        let started = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(Mutex::new(Vec::new()));
        let mut router = Router::new();
        router
            .add_tool(ConcurrentModernTool::new(
                Arc::clone(&started),
                Arc::clone(&completed),
            ))
            .expect("tool registration succeeds");
        let router = Arc::new(router);
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("the test runtime is available");
        let runtime_handle = runtime.handle();
        let (cancel_control_sender, mut cancel_control) = oneshot::channel();
        let mut cancelled = spawn_owned_modern_request(
            &runtime_handle,
            Arc::clone(&router),
            403,
            "modern-cancelled",
            "cancelled",
            Some(cancel_control_sender),
        );
        let mut sibling = spawn_owned_modern_request(
            &runtime_handle,
            router,
            404,
            "modern-sibling",
            "sibling",
            None,
        );

        let (cancelled, sibling) = runtime.block_on(async {
            let observer_cx = Cx::current().expect("block_on installs an observer context");
            let cancelled_cx = cancel_control
                .recv(&observer_cx)
                .await
                .expect("the request owner exposes its cancellation context");
            // Bounded so a dispatch rejection fails the test loudly instead of
            // spinning this observer loop forever.
            let admission_deadline = std::time::Instant::now() + Duration::from_secs(10);
            while started.load(Ordering::SeqCst) < 2 {
                assert!(
                    std::time::Instant::now() < admission_deadline,
                    "both owned modern requests must start before the admission deadline"
                );
                yield_once().await;
            }
            cancelled_cx.cancel_with(CancelKind::User, Some("test single-request cancellation"));
            let cancelled = cancelled
                .recv(&observer_cx)
                .await
                .expect("the cancelled owner reports a terminal result");
            let sibling = sibling
                .recv(&observer_cx)
                .await
                .expect("the sibling owner reports a terminal result");
            (cancelled, sibling)
        });

        let cancelled = cancelled.expect_err("only the selected request is cancelled");
        assert_eq!(cancelled.code, McpErrorCode::RequestCancelled);
        let sibling = sibling.expect("the sibling completes despite peer cancellation");
        assert_eq!(
            sibling.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(
            completed
                .lock()
                .expect("completion probe lock is not poisoned")
                .as_slice(),
            ["sibling"],
            "cancelling one request cannot add, remove, or alter sibling completion"
        );
    }

    #[test]
    fn mount_result_with_warning_and_no_error_is_successful() {
        let result = MountResult {
            tools: 0,
            resources: 0,
            resource_templates: 0,
            prompts: 0,
            warnings: vec!["something".to_string()],
            errors: vec![],
        };
        assert!(result.is_success());
        assert!(!result.has_components());
    }
}
