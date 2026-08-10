//! Proxy/composition support for MCP servers.
//!
//! This module provides lightweight proxy handlers that forward tool/resource/prompt
//! calls to another MCP server via a backend client.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use fastmcp_client::http_executor::{
    LegacySseHttpClient, ModernHttpClient, ModernHttpResponseKind,
};
use fastmcp_client::sse::SseLimits;
use fastmcp_client::{Client, ClientHttpConnection, ClientProtocolPlan};
use fastmcp_core::{CanonicalHttpUrl, McpContext, McpError, McpResult, block_on};
use fastmcp_protocol::common_types::RawIcon;
use fastmcp_protocol::methods::translate_legacy_2024_result;
use fastmcp_protocol::protocol_policy::{
    HttpEndpointBundle, HttpEndpointBundleKey, HttpEraCache, HttpEraDecision, HttpModernProbe,
    ModernVersionSupport, ProtocolEra, ProtocolPolicy, ProtocolVersion, StdioEraClassifier,
    StdioEraDecision, StdioOpeningFrame,
};
use fastmcp_protocol::{
    CacheScope, CacheTtl, CallToolResult, CancellationSender, CancellationWireMessage,
    ClientCapabilities, ClientInfo, CompleteResult, Content, CoreRequest, CoreResult,
    CreateMessageParams, FinalCallToolResult, FinalCoreResult, FinalGetPromptResult,
    FinalProgressNotificationParams, FinalReadResourceResult, FinalRequestMeta, GetPromptResult,
    InitializeParams, InitializeResult, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse,
    LegacyContent, LegacyCoreResult, LegacyPromptMessage, LegacyResourceContent, ListRootsParams,
    ListRootsResult, Prompt, PromptMessage, ReadResourceResult, RequestId, Resource,
    ResourceContent, ResourceTemplate, ServerNotification, Tool, ToolAnnotations,
    decode_strict_jsonrpc_message,
};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::handler::{
    FinalResourceReadCacheHintProvenance, FinalToolSchemaAuthority, PromptHandler, ResourceHandler,
    ToolHandler, UpstreamFinalToolSchemaRegistration, UriParams,
};

/// Progress callback signature used by proxy backends.
pub type ProgressCallback<'a> = &'a mut dyn FnMut(f64, Option<f64>, Option<String>);

/// Exact-final progress callback signature used by typed proxy calls.
///
/// This is intentionally separate from [`ProgressCallback`]: the legacy
/// callback's `f64` fields cannot retain exact final JSON-number spellings.
/// Callers that selected the modern upstream receive the admitted final
/// parameters, including their raw decimal/exponent lexemes.
pub type FinalProgressCallback<'a> = &'a mut dyn FnMut(FinalProgressNotificationParams);

/// One exact final cache policy returned with a catalog page.
///
/// A proxy materializes catalog pages into one local snapshot, but cache hints
/// belong to their individual upstream responses. Retaining one record per
/// page keeps both the arbitrary-width TTL token and the selected sharing
/// scope available to callers without inventing a synthetic aggregate policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCatalogCacheHint {
    /// Exact upstream final cache lifetime.
    pub ttl_ms: CacheTtl,
    /// Exact upstream final cache sharing scope.
    pub cache_scope: CacheScope,
}

impl ProxyCatalogCacheHint {
    fn new(ttl_ms: CacheTtl, cache_scope: CacheScope) -> Self {
        Self {
            ttl_ms,
            cache_scope,
        }
    }
}

/// Materialized final catalog entries plus each upstream page's cache policy.
#[derive(Debug, Clone)]
pub struct ProxyFinalCatalog<T> {
    /// Entries in upstream page order.
    pub entries: Vec<T>,
    /// Cache hints in the matching upstream page order.
    pub cache_hints: Vec<ProxyCatalogCacheHint>,
}

impl<T> ProxyFinalCatalog<T> {
    /// Constructs a locally supplied final catalog without an upstream page.
    #[must_use]
    pub fn new(entries: Vec<T>) -> Self {
        Self {
            entries,
            cache_hints: Vec::new(),
        }
    }

    fn single_page(entries: Vec<T>, ttl_ms: CacheTtl, cache_scope: CacheScope) -> Self {
        Self {
            entries,
            cache_hints: vec![ProxyCatalogCacheHint::new(ttl_ms, cache_scope)],
        }
    }

    /// Returns the number of materialized entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the materialized catalog has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns entries in upstream page order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.entries
    }
}

impl<T> IntoIterator for ProxyFinalCatalog<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<T> std::ops::Deref for ProxyFinalCatalog<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

/// Tool definitions returned by a proxy backend's selected protocol era.
///
/// The two variants deliberately remain disjoint: converting a final tool to
/// the legacy type would erase final-only catalog state such as its title,
/// complete icon collection, and `_meta` members.
#[derive(Debug, Clone)]
pub enum ProxyToolCatalog {
    /// Exact MCP 2024-11-05 tool definitions.
    Legacy(Vec<Tool>),
    /// Exact MCP 2026-07-28 tool definitions.
    Final(ProxyFinalCatalog<fastmcp_protocol::FinalTool>),
}

/// Resource definitions returned by a proxy backend's selected protocol era.
///
/// Final entries stay disjoint from [`Resource`]: their title, icon set,
/// annotations, size, and `_meta` members have no lossless legacy model.
#[derive(Debug, Clone)]
pub enum ProxyResourceCatalog {
    /// Exact MCP 2024-11-05 resource definitions.
    Legacy(Vec<Resource>),
    /// Exact MCP 2026-07-28 resource definitions.
    Final(ProxyFinalCatalog<fastmcp_protocol::FinalResource>),
}

/// Resource-template definitions returned by a proxy backend's selected era.
#[derive(Debug, Clone)]
pub enum ProxyResourceTemplateCatalog {
    /// Exact MCP 2024-11-05 resource template definitions.
    Legacy(Vec<ResourceTemplate>),
    /// Exact MCP 2026-07-28 resource template definitions.
    Final(ProxyFinalCatalog<fastmcp_protocol::FinalResourceTemplate>),
}

/// Prompt definitions returned by a proxy backend's selected protocol era.
#[derive(Debug, Clone)]
pub enum ProxyPromptCatalog {
    /// Exact MCP 2024-11-05 prompt definitions.
    Legacy(Vec<Prompt>),
    /// Exact MCP 2026-07-28 prompt definitions.
    Final(ProxyFinalCatalog<fastmcp_protocol::FinalPrompt>),
}

/// Complete proxy catalog without projecting its selected upstream era.
///
/// This is the public discovery surface for automatic dual-era proxies. It
/// deliberately contains disjoint per-method variants rather than a caller
/// supplied era switch: a live backend selects its era during initialization
/// and each catalog response retains that exact representation.
#[derive(Debug, Clone)]
pub struct ProxyTypedCatalog {
    /// Exact selected-era tool catalog.
    pub tools: ProxyToolCatalog,
    /// Exact selected-era resource catalog.
    pub resources: ProxyResourceCatalog,
    /// Exact selected-era resource-template catalog.
    pub resource_templates: ProxyResourceTemplateCatalog,
    /// Exact selected-era prompt catalog.
    pub prompts: ProxyPromptCatalog,
}

impl ProxyTypedCatalog {
    /// Returns final tools when the upstream negotiation selected MCP 2026-07-28.
    #[must_use]
    pub fn final_tools(&self) -> Option<&[fastmcp_protocol::FinalTool]> {
        match &self.tools {
            ProxyToolCatalog::Legacy(_) => None,
            ProxyToolCatalog::Final(tools) => Some(tools.as_slice()),
        }
    }

    /// Returns final resources when the upstream negotiation selected MCP 2026-07-28.
    #[must_use]
    pub fn final_resources(&self) -> Option<&[fastmcp_protocol::FinalResource]> {
        match &self.resources {
            ProxyResourceCatalog::Legacy(_) => None,
            ProxyResourceCatalog::Final(resources) => Some(resources.as_slice()),
        }
    }

    /// Returns final resource templates when the upstream selected MCP 2026-07-28.
    #[must_use]
    pub fn final_resource_templates(&self) -> Option<&[fastmcp_protocol::FinalResourceTemplate]> {
        match &self.resource_templates {
            ProxyResourceTemplateCatalog::Legacy(_) => None,
            ProxyResourceTemplateCatalog::Final(templates) => Some(templates.as_slice()),
        }
    }

    /// Returns final prompts when the upstream negotiation selected MCP 2026-07-28.
    #[must_use]
    pub fn final_prompts(&self) -> Option<&[fastmcp_protocol::FinalPrompt]> {
        match &self.prompts {
            ProxyPromptCatalog::Legacy(_) => None,
            ProxyPromptCatalog::Final(prompts) => Some(prompts.as_slice()),
        }
    }

    /// Returns the single era shared by every upstream catalog response.
    ///
    /// A backend is one negotiated upstream session, so a mixed catalog would
    /// prove either a stale/replaced connection or an invalid backend rather
    /// than a valid bridge result.
    pub fn era(&self) -> McpResult<ProtocolEra> {
        let tools = match &self.tools {
            ProxyToolCatalog::Legacy(_) => ProtocolEra::Legacy2024,
            ProxyToolCatalog::Final(_) => ProtocolEra::Modern2026,
        };
        let resources = match &self.resources {
            ProxyResourceCatalog::Legacy(_) => ProtocolEra::Legacy2024,
            ProxyResourceCatalog::Final(_) => ProtocolEra::Modern2026,
        };
        let templates = match &self.resource_templates {
            ProxyResourceTemplateCatalog::Legacy(_) => ProtocolEra::Legacy2024,
            ProxyResourceTemplateCatalog::Final(_) => ProtocolEra::Modern2026,
        };
        let prompts = match &self.prompts {
            ProxyPromptCatalog::Legacy(_) => ProtocolEra::Legacy2024,
            ProxyPromptCatalog::Final(_) => ProtocolEra::Modern2026,
        };
        if [resources, templates, prompts]
            .into_iter()
            .all(|era| era == tools)
        {
            Ok(tools)
        } else {
            Err(McpError::invalid_request(
                "Proxy upstream returned mixed-era catalog responses",
            ))
        }
    }
}

/// Backend interface used by proxy handlers.
pub trait ProxyBackend: Send {
    /// Lists available tools.
    fn list_tools(&mut self) -> McpResult<Vec<Tool>>;

    /// Lists tool definitions without changing their selected protocol-era model.
    ///
    /// Existing backends that implement only the legacy handler surface retain
    /// their exact behavior through the default implementation. Backends that
    /// can select the final era override this method instead of projecting
    /// [`fastmcp_protocol::FinalTool`] into [`Tool`].
    fn list_tool_catalog(&mut self) -> McpResult<ProxyToolCatalog> {
        self.list_tools().map(ProxyToolCatalog::Legacy)
    }

    /// Lists available resources.
    fn list_resources(&mut self) -> McpResult<Vec<Resource>>;
    /// Lists resource definitions without changing their selected protocol-era model.
    fn list_resource_catalog(&mut self) -> McpResult<ProxyResourceCatalog> {
        self.list_resources().map(ProxyResourceCatalog::Legacy)
    }
    /// Lists available resource templates.
    fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>>;
    /// Lists resource-template definitions without changing their selected protocol-era model.
    fn list_resource_template_catalog(&mut self) -> McpResult<ProxyResourceTemplateCatalog> {
        self.list_resource_templates()
            .map(ProxyResourceTemplateCatalog::Legacy)
    }
    /// Lists available prompts.
    fn list_prompts(&mut self) -> McpResult<Vec<Prompt>>;
    /// Lists prompt definitions without changing their selected protocol-era model.
    fn list_prompt_catalog(&mut self) -> McpResult<ProxyPromptCatalog> {
        self.list_prompts().map(ProxyPromptCatalog::Legacy)
    }
    /// Calls a tool.
    fn call_tool(&mut self, name: &str, arguments: serde_json::Value) -> McpResult<Vec<Content>>;
    /// Calls a tool with progress callback support.
    fn call_tool_with_progress(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
        on_progress: ProgressCallback<'_>,
    ) -> McpResult<Vec<Content>>;
    /// Reads a resource by URI.
    fn read_resource(&mut self, uri: &str) -> McpResult<Vec<ResourceContent>>;
    /// Fetches a prompt by name.
    fn get_prompt(
        &mut self,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>>;

    /// Calls a tool while retaining the exact response model selected upstream.
    ///
    /// Historical backends only provide closed handler content, which can be
    /// re-authored as an exact legacy result. Live dual-era clients override
    /// this hook so final payloads never pass through `Content`.
    fn call_tool_result(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<CoreResult> {
        Ok(CoreResult::Legacy(LegacyCoreResult::ToolsCall(
            CallToolResult {
                content: handler_contents_to_legacy(self.call_tool(name, arguments)?)?,
                is_error: false,
                meta: None,
                additional: BTreeMap::new(),
            },
        )))
    }

    /// Calls a tool while forwarding exact-final progress notifications.
    ///
    /// Legacy backends retain their separate progress callback behavior and
    /// therefore ignore this final-only callback by default.
    fn call_tool_result_with_final_progress(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
        _on_progress: FinalProgressCallback<'_>,
    ) -> McpResult<CoreResult> {
        self.call_tool_result(name, arguments)
    }

    /// Reads a resource while retaining the exact response model selected upstream.
    fn read_resource_result(&mut self, uri: &str) -> McpResult<CoreResult> {
        Ok(CoreResult::Legacy(LegacyCoreResult::ResourcesRead(
            ReadResourceResult {
                contents: self
                    .read_resource(uri)?
                    .into_iter()
                    .map(handler_resource_to_legacy)
                    .collect::<McpResult<Vec<_>>>()?,
                meta: None,
                additional: BTreeMap::new(),
            },
        )))
    }

    /// Gets a prompt while retaining the exact response model selected upstream.
    fn get_prompt_result(
        &mut self,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<CoreResult> {
        Ok(CoreResult::Legacy(LegacyCoreResult::PromptsGet(
            GetPromptResult {
                description: None,
                messages: self
                    .get_prompt(name, arguments)?
                    .into_iter()
                    .map(handler_prompt_to_legacy)
                    .collect::<McpResult<Vec<_>>>()?,
                meta: None,
                additional: BTreeMap::new(),
            },
        )))
    }
}

/// Refuses fields which have no representation in the proxy handler surface.
///
/// The handler API intentionally exposes the older closed content types. An
/// exact legacy or final wire payload must therefore be rejected whenever
/// projecting it would erase annotations, metadata, or extension members.
fn reject_lossy_proxy_projection(
    context: &str,
    annotations_present: bool,
    metadata_present: bool,
    additional: &BTreeMap<String, serde_json::Value>,
) -> McpResult<()> {
    if annotations_present {
        return Err(McpError::invalid_request(format!(
            "Proxy cannot losslessly project {context}: annotations are unsupported by proxy handler types"
        )));
    }
    if metadata_present {
        return Err(McpError::invalid_request(format!(
            "Proxy cannot losslessly project {context}: metadata is unsupported by proxy handler types"
        )));
    }
    if !additional.is_empty() {
        return Err(McpError::invalid_request(format!(
            "Proxy cannot losslessly project {context}: open fields are unsupported by proxy handler types"
        )));
    }
    Ok(())
}

/// Projects exact 2024-11-05 content into the closed proxy handler surface.
fn legacy_content_to_handler(content: LegacyContent) -> McpResult<Content> {
    match content {
        LegacyContent::Text {
            text,
            annotations,
            additional,
        } => {
            reject_lossy_proxy_projection(
                "legacy text content",
                annotations.is_some(),
                false,
                &additional,
            )?;
            Ok(Content::Text { text })
        }
        LegacyContent::Image {
            data,
            mime_type,
            annotations,
            additional,
        } => {
            reject_lossy_proxy_projection(
                "legacy image content",
                annotations.is_some(),
                false,
                &additional,
            )?;
            Ok(Content::Image { data, mime_type })
        }
        LegacyContent::Resource {
            resource,
            annotations,
            additional,
        } => {
            reject_lossy_proxy_projection(
                "legacy resource content",
                annotations.is_some(),
                false,
                &additional,
            )?;
            Ok(Content::Resource {
                resource: legacy_resource_to_handler(resource)?,
            })
        }
    }
}

fn legacy_contents_to_handler(contents: Vec<LegacyContent>) -> McpResult<Vec<Content>> {
    contents
        .into_iter()
        .map(legacy_content_to_handler)
        .collect()
}

/// Projects exact 2024-11-05 resource content only when it has no open state.
fn legacy_resource_to_handler(resource: LegacyResourceContent) -> McpResult<ResourceContent> {
    match resource {
        LegacyResourceContent::Text {
            uri,
            text,
            mime_type,
            additional,
        } => {
            reject_lossy_proxy_projection("legacy text resource", false, false, &additional)?;
            Ok(ResourceContent {
                uri,
                mime_type,
                text: Some(text),
                blob: None,
            })
        }
        LegacyResourceContent::Blob {
            uri,
            blob,
            mime_type,
            additional,
        } => {
            reject_lossy_proxy_projection("legacy blob resource", false, false, &additional)?;
            Ok(ResourceContent {
                uri,
                mime_type,
                text: None,
                blob: Some(blob),
            })
        }
    }
}

fn legacy_resources_to_handler(
    resources: Vec<LegacyResourceContent>,
) -> McpResult<Vec<ResourceContent>> {
    resources
        .into_iter()
        .map(legacy_resource_to_handler)
        .collect()
}

fn legacy_prompt_message_to_handler(message: LegacyPromptMessage) -> McpResult<PromptMessage> {
    reject_lossy_proxy_projection("legacy prompt message", false, false, &message.additional)?;
    Ok(PromptMessage {
        role: message.role,
        content: legacy_content_to_handler(message.content)?,
    })
}

fn legacy_prompt_messages_to_handler(
    messages: Vec<LegacyPromptMessage>,
) -> McpResult<Vec<PromptMessage>> {
    messages
        .into_iter()
        .map(legacy_prompt_message_to_handler)
        .collect()
}

fn legacy_tool_result_to_handler(result: CallToolResult) -> McpResult<Vec<Content>> {
    reject_lossy_proxy_projection(
        "legacy tools/call result",
        false,
        result.meta.is_some(),
        &result.additional,
    )?;
    if result.is_error {
        return Err(McpError::tool_error(
            "Proxy cannot project a legacy tools/call error result as successful handler content",
        ));
    }
    legacy_contents_to_handler(result.content)
}

fn legacy_resource_result_to_handler(
    result: ReadResourceResult,
) -> McpResult<Vec<ResourceContent>> {
    reject_lossy_proxy_projection(
        "legacy resources/read result",
        false,
        result.meta.is_some(),
        &result.additional,
    )?;
    legacy_resources_to_handler(result.contents)
}

fn legacy_prompt_result_to_handler(result: GetPromptResult) -> McpResult<Vec<PromptMessage>> {
    reject_lossy_proxy_projection(
        "legacy prompts/get result",
        false,
        result.meta.is_some(),
        &result.additional,
    )?;
    legacy_prompt_messages_to_handler(result.messages)
}

/// Re-encodes the closed historical handler surface as an exact legacy result.
///
/// Generic proxy backends implement the historical handler callbacks. Those
/// values carry no open state, so they can be admitted only when they have an
/// exact 2024 representation. Audio and malformed embedded resources have no
/// such representation and remain fail-closed.
fn handler_content_to_legacy(content: Content) -> McpResult<LegacyContent> {
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
        Content::Resource { resource } => {
            let resource = match (resource.text, resource.blob) {
                (Some(text), None) => LegacyResourceContent::Text {
                    uri: resource.uri,
                    text,
                    mime_type: resource.mime_type,
                    additional: BTreeMap::new(),
                },
                (None, Some(blob)) => LegacyResourceContent::Blob {
                    uri: resource.uri,
                    blob,
                    mime_type: resource.mime_type,
                    additional: BTreeMap::new(),
                },
                _ => {
                    return Err(McpError::invalid_request(
                        "Proxy handler resource has no exact legacy representation",
                    ));
                }
            };
            Ok(LegacyContent::Resource {
                resource,
                annotations: None,
                additional: BTreeMap::new(),
            })
        }
        Content::Audio { .. } => Err(McpError::invalid_request(
            "Proxy handler audio has no exact legacy representation",
        )),
    }
}

fn handler_contents_to_legacy(contents: Vec<Content>) -> McpResult<Vec<LegacyContent>> {
    contents
        .into_iter()
        .map(handler_content_to_legacy)
        .collect()
}

fn handler_resource_to_legacy(resource: ResourceContent) -> McpResult<LegacyResourceContent> {
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
        _ => Err(McpError::invalid_request(
            "Proxy handler resource has no exact legacy representation",
        )),
    }
}

fn handler_prompt_to_legacy(message: PromptMessage) -> McpResult<LegacyPromptMessage> {
    Ok(LegacyPromptMessage {
        role: message.role,
        content: handler_content_to_legacy(message.content)?,
        additional: BTreeMap::new(),
    })
}

/// Maximum pages the proxy will acquire while materializing one modern catalog.
///
/// Proxy registration creates a fixed downstream snapshot, so every page must
/// be collected before any entry is registered. The bound keeps an upstream
/// cursor cycle or an unbounded catalog from turning that one-time operation
/// into unbounded work.
const MAX_MODERN_PROXY_CATALOG_PAGES: usize = 64;

/// Collects one paginated modern catalog without accepting a cursor cycle.
///
/// The caller owns selected-era decoding; this helper owns only the invariant
/// shared by tools, resources, templates, and prompts. Returning an error
/// drops the locally accumulated entries, so the caller cannot construct a
/// partial proxy catalog after an invalid cursor sequence.
fn collect_modern_proxy_catalog_pages<T>(
    method: &str,
    mut fetch_page: impl FnMut(
        Option<&str>,
    ) -> McpResult<(Vec<T>, Option<String>, ProxyCatalogCacheHint)>,
) -> McpResult<ProxyFinalCatalog<T>> {
    let mut entries = Vec::new();
    let mut cache_hints = Vec::new();
    let mut cursor = None;
    let mut observed_cursors = HashSet::new();

    for _ in 0..MAX_MODERN_PROXY_CATALOG_PAGES {
        let (page, next_cursor, cache_hint) = fetch_page(cursor.as_deref())?;
        entries.extend(page);
        cache_hints.push(cache_hint);

        let Some(next_cursor) = next_cursor else {
            return Ok(ProxyFinalCatalog {
                entries,
                cache_hints,
            });
        };
        if cursor.as_deref() == Some(next_cursor.as_str()) {
            return Err(McpError::invalid_request(format!(
                "Proxy modern {method} catalog returned a non-advancing cursor"
            )));
        }
        if !observed_cursors.insert(next_cursor.clone()) {
            return Err(McpError::invalid_request(format!(
                "Proxy modern {method} catalog returned a repeated cursor"
            )));
        }
        cursor = Some(next_cursor);
    }

    Err(McpError::invalid_request(format!(
        "Proxy modern {method} catalog exceeded its {MAX_MODERN_PROXY_CATALOG_PAGES}-page limit"
    )))
}

impl ProxyBackend for Client {
    fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
        self.ensure_initialized()?;
        if self.server_capabilities().tools.is_none() {
            return Ok(Vec::new());
        }
        Client::list_tools(self)
    }

    fn list_tool_catalog(&mut self) -> McpResult<ProxyToolCatalog> {
        self.ensure_initialized()?;
        let era = self.selected_protocol_era().ok_or_else(|| {
            McpError::invalid_request("Proxy client has no selected protocol era for tools/list")
        })?;
        match era {
            ProtocolEra::Legacy2024 => {
                if self.server_capabilities().tools.is_none() {
                    Ok(ProxyToolCatalog::Legacy(Vec::new()))
                } else {
                    Client::list_tools(self).map(ProxyToolCatalog::Legacy)
                }
            }
            ProtocolEra::Modern2026 => collect_modern_proxy_catalog_pages(
                fastmcp_protocol::methods::TOOLS_LIST,
                |cursor| match Client::list_tools_typed(self, cursor)? {
                    CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) => {
                        let payload = result.payload;
                        Ok((
                            payload.tools,
                            payload.next_cursor,
                            ProxyCatalogCacheHint::new(payload.ttl_ms, payload.cache_scope),
                        ))
                    }
                    CoreResult::Legacy(LegacyCoreResult::ToolsList(_)) => {
                        Err(McpError::invalid_request(
                            "Modern proxy client received a legacy tools/list result",
                        ))
                    }
                    _ => Err(unexpected_proxy_result("tools/list")),
                },
            )
            .map(ProxyToolCatalog::Final),
        }
    }

    fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        self.ensure_initialized()?;
        if self.server_capabilities().resources.is_none() {
            return Ok(Vec::new());
        }
        Client::list_resources(self)
    }

    fn list_resource_catalog(&mut self) -> McpResult<ProxyResourceCatalog> {
        self.ensure_initialized()?;
        let era = self.selected_protocol_era().ok_or_else(|| {
            McpError::invalid_request(
                "Proxy client has no selected protocol era for resources/list",
            )
        })?;
        match era {
            ProtocolEra::Legacy2024 => {
                if self.server_capabilities().resources.is_none() {
                    return Ok(ProxyResourceCatalog::Legacy(Vec::new()));
                }
                match Client::list_resources_typed(self, None)? {
                    CoreResult::Legacy(LegacyCoreResult::ResourcesList(result)) => {
                        Ok(ProxyResourceCatalog::Legacy(result.resources))
                    }
                    CoreResult::Final(FinalCoreResult::ResourcesList { result, .. }) => {
                        let payload = result.payload;
                        Ok(ProxyResourceCatalog::Final(ProxyFinalCatalog::single_page(
                            payload.resources,
                            payload.ttl_ms,
                            payload.cache_scope,
                        )))
                    }
                    _ => Err(unexpected_proxy_result("resources/list")),
                }
            }
            ProtocolEra::Modern2026 => collect_modern_proxy_catalog_pages(
                fastmcp_protocol::methods::RESOURCES_LIST,
                |cursor| match Client::list_resources_typed(self, cursor)? {
                    CoreResult::Final(FinalCoreResult::ResourcesList { result, .. }) => {
                        let payload = result.payload;
                        Ok((
                            payload.resources,
                            payload.next_cursor,
                            ProxyCatalogCacheHint::new(payload.ttl_ms, payload.cache_scope),
                        ))
                    }
                    CoreResult::Legacy(LegacyCoreResult::ResourcesList(_)) => {
                        Err(McpError::invalid_request(
                            "Modern proxy client received a legacy resources/list result",
                        ))
                    }
                    _ => Err(unexpected_proxy_result("resources/list")),
                },
            )
            .map(ProxyResourceCatalog::Final),
        }
    }

    fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
        self.ensure_initialized()?;
        if self.server_capabilities().resources.is_none() {
            return Ok(Vec::new());
        }
        Client::list_resource_templates(self)
    }

    fn list_resource_template_catalog(&mut self) -> McpResult<ProxyResourceTemplateCatalog> {
        self.ensure_initialized()?;
        let era = self.selected_protocol_era().ok_or_else(|| {
            McpError::invalid_request(
                "Proxy client has no selected protocol era for resources/templates/list",
            )
        })?;
        match era {
            ProtocolEra::Legacy2024 => {
                if self.server_capabilities().resources.is_none() {
                    return Ok(ProxyResourceTemplateCatalog::Legacy(Vec::new()));
                }
                match Client::list_resource_templates_typed(self, None)? {
                    CoreResult::Legacy(LegacyCoreResult::ResourceTemplatesList(result)) => Ok(
                        ProxyResourceTemplateCatalog::Legacy(result.resource_templates),
                    ),
                    CoreResult::Final(FinalCoreResult::ResourceTemplatesList {
                        result, ..
                    }) => {
                        let payload = result.payload;
                        Ok(ProxyResourceTemplateCatalog::Final(
                            ProxyFinalCatalog::single_page(
                                payload.resource_templates,
                                payload.ttl_ms,
                                payload.cache_scope,
                            ),
                        ))
                    }
                    _ => Err(unexpected_proxy_result("resources/templates/list")),
                }
            }
            ProtocolEra::Modern2026 => collect_modern_proxy_catalog_pages(
                fastmcp_protocol::methods::RESOURCES_TEMPLATES_LIST,
                |cursor| match Client::list_resource_templates_typed(self, cursor)? {
                    CoreResult::Final(FinalCoreResult::ResourceTemplatesList {
                        result, ..
                    }) => {
                        let payload = result.payload;
                        Ok((
                            payload.resource_templates,
                            payload.next_cursor,
                            ProxyCatalogCacheHint::new(payload.ttl_ms, payload.cache_scope),
                        ))
                    }
                    CoreResult::Legacy(LegacyCoreResult::ResourceTemplatesList(_)) => {
                        Err(McpError::invalid_request(
                            "Modern proxy client received a legacy resources/templates/list result",
                        ))
                    }
                    _ => Err(unexpected_proxy_result("resources/templates/list")),
                },
            )
            .map(ProxyResourceTemplateCatalog::Final),
        }
    }

    fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
        self.ensure_initialized()?;
        if self.server_capabilities().prompts.is_none() {
            return Ok(Vec::new());
        }
        Client::list_prompts(self)
    }

    fn list_prompt_catalog(&mut self) -> McpResult<ProxyPromptCatalog> {
        self.ensure_initialized()?;
        let era = self.selected_protocol_era().ok_or_else(|| {
            McpError::invalid_request("Proxy client has no selected protocol era for prompts/list")
        })?;
        match era {
            ProtocolEra::Legacy2024 => {
                if self.server_capabilities().prompts.is_none() {
                    return Ok(ProxyPromptCatalog::Legacy(Vec::new()));
                }
                match Client::list_prompts_typed(self, None)? {
                    CoreResult::Legacy(LegacyCoreResult::PromptsList(result)) => {
                        Ok(ProxyPromptCatalog::Legacy(result.prompts))
                    }
                    CoreResult::Final(FinalCoreResult::PromptsList { result, .. }) => {
                        let payload = result.payload;
                        Ok(ProxyPromptCatalog::Final(ProxyFinalCatalog::single_page(
                            payload.prompts,
                            payload.ttl_ms,
                            payload.cache_scope,
                        )))
                    }
                    _ => Err(unexpected_proxy_result("prompts/list")),
                }
            }
            ProtocolEra::Modern2026 => collect_modern_proxy_catalog_pages(
                fastmcp_protocol::methods::PROMPTS_LIST,
                |cursor| match Client::list_prompts_typed(self, cursor)? {
                    CoreResult::Final(FinalCoreResult::PromptsList { result, .. }) => {
                        let payload = result.payload;
                        Ok((
                            payload.prompts,
                            payload.next_cursor,
                            ProxyCatalogCacheHint::new(payload.ttl_ms, payload.cache_scope),
                        ))
                    }
                    CoreResult::Legacy(LegacyCoreResult::PromptsList(_)) => {
                        Err(McpError::invalid_request(
                            "Modern proxy client received a legacy prompts/list result",
                        ))
                    }
                    _ => Err(unexpected_proxy_result("prompts/list")),
                },
            )
            .map(ProxyPromptCatalog::Final),
        }
    }

    fn call_tool(&mut self, name: &str, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        legacy_contents_to_handler(Client::call_tool(self, name, arguments)?)
    }

    fn call_tool_with_progress(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
        on_progress: ProgressCallback<'_>,
    ) -> McpResult<Vec<Content>> {
        let mut wrapper = |progress, total, message: Option<&str>| {
            on_progress(progress, total, message.map(ToString::to_string));
        };
        legacy_contents_to_handler(Client::call_tool_with_progress(
            self,
            name,
            arguments,
            &mut wrapper,
        )?)
    }

    fn read_resource(&mut self, uri: &str) -> McpResult<Vec<ResourceContent>> {
        legacy_resources_to_handler(Client::read_resource(self, uri)?)
    }

    fn get_prompt(
        &mut self,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        legacy_prompt_messages_to_handler(Client::get_prompt(self, name, arguments)?)
    }

    fn call_tool_result(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<CoreResult> {
        match Client::call_tool_typed(self, name, arguments)? {
            result @ CoreResult::Legacy(LegacyCoreResult::ToolsCall(_))
            | result @ CoreResult::Final(FinalCoreResult::ToolsCall { .. }) => Ok(result),
            _ => Err(unexpected_proxy_result("tools/call")),
        }
    }

    fn read_resource_result(&mut self, uri: &str) -> McpResult<CoreResult> {
        match Client::read_resource_typed(self, uri)? {
            result @ CoreResult::Legacy(LegacyCoreResult::ResourcesRead(_))
            | result @ CoreResult::Final(FinalCoreResult::ResourcesRead { .. }) => Ok(result),
            _ => Err(unexpected_proxy_result("resources/read")),
        }
    }

    fn get_prompt_result(
        &mut self,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<CoreResult> {
        match Client::get_prompt_typed(self, name, arguments)? {
            result @ CoreResult::Legacy(LegacyCoreResult::PromptsGet(_))
            | result @ CoreResult::Final(FinalCoreResult::PromptsGet { .. }) => Ok(result),
            _ => Err(unexpected_proxy_result("prompts/get")),
        }
    }
}

/// Catalog of remote definitions used to register proxy handlers.
#[derive(Debug, Clone, Default)]
pub struct ProxyCatalog {
    /// Exact protocol era selected for every upstream catalog response.
    ///
    /// The historical field name is retained, but it is a catalog-wide marker:
    /// a single upstream session must not combine legacy and final component
    /// definitions. Admission requires this explicit marker even when every
    /// component catalog is empty, so an empty final catalog is never guessed
    /// to be legacy.
    pub tool_catalog_era: Option<ProtocolEra>,
    /// Exact legacy remote tool definitions.
    pub tools: Vec<Tool>,
    /// Exact final remote tool definitions.
    ///
    /// This remains separate from [`Self::tools`] so the final catalog keeps
    /// every serializable `FinalTool` member rather than being downgraded to
    /// the legacy component model.
    pub final_tools: Vec<fastmcp_protocol::FinalTool>,
    /// Exact final `tools/list` policy for every materialized upstream page.
    pub final_tool_cache_hints: Vec<ProxyCatalogCacheHint>,
    /// Exact legacy remote resource definitions.
    pub resources: Vec<Resource>,
    /// Exact final remote resource definitions.
    pub final_resources: Vec<fastmcp_protocol::FinalResource>,
    /// Exact final `resources/list` policy for every materialized upstream page.
    pub final_resource_cache_hints: Vec<ProxyCatalogCacheHint>,
    /// Exact legacy remote resource-template definitions.
    pub resource_templates: Vec<ResourceTemplate>,
    /// Exact final remote resource-template definitions.
    pub final_resource_templates: Vec<fastmcp_protocol::FinalResourceTemplate>,
    /// Exact final `resources/templates/list` policy for every materialized upstream page.
    pub final_resource_template_cache_hints: Vec<ProxyCatalogCacheHint>,
    /// Exact legacy remote prompt definitions.
    pub prompts: Vec<Prompt>,
    /// Exact final remote prompt definitions.
    pub final_prompts: Vec<fastmcp_protocol::FinalPrompt>,
    /// Exact final `prompts/list` policy for every materialized upstream page.
    pub final_prompt_cache_hints: Vec<ProxyCatalogCacheHint>,
}

impl ProxyCatalog {
    /// Builds a catalog by querying a proxy backend.
    pub fn from_backend<B: ProxyBackend + ?Sized>(backend: &mut B) -> McpResult<Self> {
        let (tool_catalog_era, tools, final_tools, final_tool_cache_hints) =
            match backend.list_tool_catalog()? {
                ProxyToolCatalog::Legacy(tools) => {
                    (Some(ProtocolEra::Legacy2024), tools, Vec::new(), Vec::new())
                }
                ProxyToolCatalog::Final(tools) => (
                    Some(ProtocolEra::Modern2026),
                    Vec::new(),
                    tools.entries,
                    tools.cache_hints,
                ),
            };
        let (resources, final_resources, final_resource_cache_hints) =
            match backend.list_resource_catalog()? {
                ProxyResourceCatalog::Legacy(resources) => (resources, Vec::new(), Vec::new()),
                ProxyResourceCatalog::Final(resources) => {
                    (Vec::new(), resources.entries, resources.cache_hints)
                }
            };
        let (resource_templates, final_resource_templates, final_resource_template_cache_hints) =
            match backend.list_resource_template_catalog()? {
                ProxyResourceTemplateCatalog::Legacy(resource_templates) => {
                    (resource_templates, Vec::new(), Vec::new())
                }
                ProxyResourceTemplateCatalog::Final(resource_templates) => (
                    Vec::new(),
                    resource_templates.entries,
                    resource_templates.cache_hints,
                ),
            };
        let (prompts, final_prompts, final_prompt_cache_hints) =
            match backend.list_prompt_catalog()? {
                ProxyPromptCatalog::Legacy(prompts) => (prompts, Vec::new(), Vec::new()),
                ProxyPromptCatalog::Final(prompts) => {
                    (Vec::new(), prompts.entries, prompts.cache_hints)
                }
            };
        let catalog = Self {
            tool_catalog_era,
            tools,
            final_tools,
            final_tool_cache_hints,
            resources,
            final_resources,
            final_resource_cache_hints,
            resource_templates,
            final_resource_templates,
            final_resource_template_cache_hints,
            prompts,
            final_prompts,
            final_prompt_cache_hints,
        };
        catalog.admit_catalog_shape()?;
        Ok(catalog)
    }

    /// Builds a catalog by querying a client.
    pub fn from_client(client: &mut Client) -> McpResult<Self> {
        Self::from_backend(client)
    }

    /// Creates exact-final proxy handlers without projecting their catalog
    /// definitions through the legacy [`Tool`] model.
    pub(crate) fn final_tool_handlers(
        &self,
        client: ProxyClient,
    ) -> McpResult<Vec<ProxyToolHandler>> {
        client.admit_catalog(self)?;
        self.final_tools
            .iter()
            .cloned()
            .map(|tool| ProxyToolHandler::from_final(tool, client.clone()))
            .collect()
    }

    /// Returns the one exact era selected by every catalog component.
    ///
    /// A catalog produced by a selected legacy route contains legacy entries
    /// only; a selected final route contains final entries only. The marker is
    /// mandatory even when the selected catalog is empty, because an empty
    /// final catalog must never be guessed to be legacy.
    pub fn era(&self) -> McpResult<ProtocolEra> {
        self.admit_catalog_shape()?;
        self.tool_catalog_era
            .ok_or_else(|| McpError::internal_error("admitted proxy catalog has no selected era"))
    }

    /// Refuses a catalog that combines representations from more than one era.
    ///
    /// This validation intentionally precedes route-binding admission and every
    /// builder registration path. `ProxyCatalog` remains public for callers that
    /// assemble a catalog themselves, so its vectors cannot be trusted merely
    /// because the era marker matches a bound client.
    fn admit_catalog_shape(&self) -> McpResult<()> {
        match self.tool_catalog_era {
            Some(ProtocolEra::Legacy2024)
                if self.final_tools.is_empty()
                    && self.final_resources.is_empty()
                    && self.final_resource_templates.is_empty()
                    && self.final_prompts.is_empty() =>
            {
                Ok(())
            }
            Some(ProtocolEra::Legacy2024) => Err(McpError::invalid_request(
                "An exact legacy proxy catalog must not contain final tools, resources, resource templates, or prompts",
            )),
            Some(ProtocolEra::Modern2026)
                if self.tools.is_empty()
                    && self.resources.is_empty()
                    && self.resource_templates.is_empty()
                    && self.prompts.is_empty() =>
            {
                Ok(())
            }
            Some(ProtocolEra::Modern2026) => Err(McpError::invalid_request(
                "An exact final proxy catalog must not contain legacy tools, resources, resource templates, or prompts",
            )),
            None => Err(McpError::invalid_request(
                "Proxy catalog must declare an exact legacy or final era",
            )),
        }
    }

    fn admit_upstream_binding(&self, binding: ProxyUpstreamBinding) -> McpResult<()> {
        self.admit_catalog_shape()?;
        if self.tool_catalog_era != Some(binding.era()) {
            return Err(McpError::invalid_request(
                "Proxy catalog era contradicts the immutable route binding",
            ));
        }
        Ok(())
    }
}

/// Shared proxy client wrapper for handler reuse.
#[derive(Clone)]
pub struct ProxyClient {
    inner: Arc<Mutex<dyn ProxyBackend>>,
    upstream_binding: Option<ProxyUpstreamBinding>,
}

impl std::fmt::Debug for ProxyClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyClient")
            .field("upstream_binding", &self.upstream_binding)
            .finish_non_exhaustive()
    }
}

/// Immutable adapter selected for one independently configured upstream leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyUpstreamAdapter {
    /// MCP 2026-07-28 over the upstream stdio adapter.
    ModernStdio,
    /// Exact MCP 2024-11-05 over the upstream stdio adapter.
    LegacyStdio,
    /// MCP 2026-07-28 Streamable HTTP request/response transport.
    ModernHttp,
    /// Exact MCP 2024-11-05 advertised-POST plus SSE transport.
    LegacyHttpSse,
}

/// Immutable route-local selection made before upstream lifecycle traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyUpstreamBinding {
    era: ProtocolEra,
    adapter: ProxyUpstreamAdapter,
    policy: ProtocolPolicy,
    configuration_generation: u64,
}

impl ProxyUpstreamBinding {
    /// Returns the exact era selected for this upstream only.
    #[must_use]
    pub const fn era(self) -> ProtocolEra {
        self.era
    }

    /// Returns the immutable transport adapter selected for this upstream.
    #[must_use]
    pub const fn adapter(self) -> ProxyUpstreamAdapter {
        self.adapter
    }

    /// Returns whether this immutable binding selected the exact-2024 adapter.
    #[must_use]
    pub const fn uses_legacy_adapter(self) -> bool {
        matches!(
            self.adapter,
            ProxyUpstreamAdapter::LegacyStdio | ProxyUpstreamAdapter::LegacyHttpSse
        )
    }

    /// Returns whether this immutable binding selected an HTTP adapter.
    #[must_use]
    pub const fn uses_http_transport(self) -> bool {
        matches!(
            self.adapter,
            ProxyUpstreamAdapter::ModernHttp | ProxyUpstreamAdapter::LegacyHttpSse
        )
    }

    /// Returns the policy fixed before this upstream was classified.
    #[must_use]
    pub const fn policy(self) -> ProtocolPolicy {
        self.policy
    }

    /// Returns the configuration generation included in this binding identity.
    #[must_use]
    pub const fn configuration_generation(self) -> u64 {
        self.configuration_generation
    }

    /// Admits a version only when it is the exact immutable era of this route.
    ///
    /// This is intentionally route-local: an unsupported or sibling-era value
    /// cannot cause this binding to renegotiate or alter another upstream.
    pub fn admit_upstream_protocol_version(
        self,
        protocol_version: &str,
    ) -> McpResult<ProtocolVersion> {
        let version = ProtocolVersion::parse(protocol_version)
            .map_err(|error| McpError::invalid_request(error.to_string()))?;
        if version.era() != self.era {
            return Err(McpError::invalid_request(
                "Upstream protocol version does not match the route's immutable selected era",
            ));
        }
        Ok(version)
    }

    /// Translates an upstream result only when this route selected exact 2024.
    ///
    /// Exact-2024 results must retain a lossless representation. Modern
    /// results are already on the downstream era and therefore pass through
    /// byte-for-byte without a legacy translation attempt.
    pub fn translate_upstream_result(
        self,
        method: &str,
        result: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        match self.era {
            ProtocolEra::Modern2026 => Ok(result),
            ProtocolEra::Legacy2024 => translate_legacy_2024_result(method, result)
                .map_err(|error| McpError::invalid_params(error.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StdioBindingKey {
    route_identity: String,
    transport_identity: String,
    adapter_receipt_identity: String,
    policy: ProtocolPolicy,
    configuration_generation: u64,
}

/// Cache identity for a successfully connected stdio upstream.
///
/// Unlike [`StdioBindingKey`], this key has no caller-supplied adapter-era
/// receipt. The selected era is derived only after a live client completes its
/// immutable protocol-plan handshake.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LiveStdioBindingKey {
    route_identity: String,
    transport_identity: String,
    policy: ProtocolPolicy,
    configuration_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HttpBindingKey {
    route_identity: String,
    transport_identity: String,
    adapter_receipt_identity: String,
    configuration_generation: u64,
    bundle: HttpEndpointBundleKey,
}

/// Cache identity for one live HTTP upstream client.
///
/// The complete immutable endpoint bundle keeps routes, policy, partitions,
/// and generations in the identity. A caller-supplied adapter receipt is
/// deliberately absent: this path retains the actual shipped HTTP client that
/// performed the selection rather than trusting a separate receipt.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LiveHttpBindingKey {
    route_identity: String,
    transport_identity: String,
    configuration_generation: u64,
    bundle: HttpEndpointBundleKey,
    client_info_wire: Vec<u8>,
    client_capabilities_wire: Vec<u8>,
}

/// One cached native HTTP upstream selected by an immutable protocol plan.
///
/// The enclosed connection is the shipped automatic client facade. It owns
/// either the final HTTP client or the exact legacy SSE GET plus
/// advertised-POST client after real outbound selection. [`ProxyClient`] owns
/// this backend behind its route-local mutex, so a legacy SSE stream cannot be
/// advanced concurrently or leak into another upstream's selected era.
pub struct ProxyHttpClient {
    binding: ProxyUpstreamBinding,
    connection: ClientHttpConnection,
    cx: Cx,
    client_info: ClientInfo,
    client_capabilities: ClientCapabilities,
    next_request_id: i64,
    legacy_initialized: bool,
    legacy_retired_request_ids: VecDeque<RequestId>,
}

impl std::fmt::Debug for ProxyHttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyHttpClient")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl ProxyHttpClient {
    const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

    fn sse_limits() -> SseLimits {
        SseLimits::new(64 * 1024, 2 * 1024 * 1024, 256)
            .expect("nonzero HTTP proxy SSE bounds are valid")
    }

    fn new(
        binding: ProxyUpstreamBinding,
        connection: ClientHttpConnection,
        cx: Cx,
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
    ) -> Self {
        let next_request_id = match connection.selected_protocol_era() {
            ProtocolEra::Modern2026 => 2,
            ProtocolEra::Legacy2024 => 1,
        };
        Self {
            binding,
            connection,
            cx,
            client_info,
            client_capabilities,
            next_request_id,
            legacy_initialized: false,
            legacy_retired_request_ids: VecDeque::new(),
        }
    }

    /// Returns the immutable era binding selected for this backend.
    #[must_use]
    pub const fn upstream_binding(&self) -> ProxyUpstreamBinding {
        self.binding
    }

    fn next_request_id(&mut self) -> McpResult<RequestId> {
        let id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or_else(|| McpError::internal_error("Proxy HTTP request ID sequence exhausted"))?;
        Ok(RequestId::Number(id))
    }

    fn request_parameters(
        &self,
        mut parameters: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        if self.binding.era() == ProtocolEra::Legacy2024 {
            return Ok(parameters);
        }
        let object = parameters.as_object_mut().ok_or_else(|| {
            McpError::invalid_params("Proxy HTTP request parameters must be an object")
        })?;
        let mut metadata = FinalRequestMeta::new(self.client_capabilities.clone());
        metadata.client_info = Some(self.client_info.clone());
        object.insert(
            "_meta".to_owned(),
            serde_json::to_value(metadata).map_err(|error| {
                McpError::internal_error(format!(
                    "Proxy HTTP final request metadata could not be encoded: {error}"
                ))
            })?,
        );
        Ok(parameters)
    }

    fn modern_catalog_parameters(cursor: Option<&str>) -> serde_json::Value {
        match cursor {
            Some(cursor) => serde_json::json!({"cursor": cursor}),
            None => serde_json::json!({}),
        }
    }

    fn ensure_legacy_initialized(&mut self) -> McpResult<()> {
        if self.legacy_initialized {
            return Ok(());
        }
        let request_id = self.next_request_id()?;
        let parameters = InitializeParams {
            protocol_version: fastmcp_protocol::PROTOCOL_VERSION.to_owned(),
            capabilities: self.client_capabilities.clone(),
            client_info: self.client_info.clone(),
        };
        let message = JsonRpcMessage::Request(JsonRpcRequest::new(
            fastmcp_protocol::methods::INITIALIZE,
            Some(serde_json::to_value(parameters).map_err(|error| {
                McpError::internal_error(format!(
                    "Proxy HTTP legacy initialize parameters could not be encoded: {error}"
                ))
            })?),
            request_id.clone(),
        ));
        let response = match &mut self.connection {
            ClientHttpConnection::LegacySse { client, .. } => {
                block_on(client.send(&self.cx, &message)).map_err(legacy_http_error)?;
                receive_legacy_response(
                    client,
                    &self.cx,
                    &self.client_capabilities,
                    &request_id,
                    &mut self.legacy_retired_request_ids,
                )?
            }
            ClientHttpConnection::Modern(_) => {
                return Err(McpError::internal_error(
                    "Modern HTTP proxy connection entered legacy initialization",
                ));
            }
        };
        if let Some(error) = response.error.as_ref() {
            return Err(McpError::internal_error(format!(
                "Proxy HTTP legacy initialize was rejected: {} ({})",
                error.message, error.code
            )));
        }
        let result = response.result.ok_or_else(|| {
            McpError::invalid_request("Legacy initialize response omitted its result")
        })?;
        let initialized: InitializeResult = serde_json::from_value(result).map_err(|error| {
            McpError::invalid_request(format!(
                "Legacy initialize response was invalid for the exact 2024-11-05 era: {error}"
            ))
        })?;
        if initialized.protocol_version != fastmcp_protocol::PROTOCOL_VERSION {
            return Err(McpError::invalid_request(
                "Legacy initialize response selected a protocol version other than 2024-11-05",
            ));
        }

        let notification = JsonRpcMessage::Request(JsonRpcRequest::initialized_notification());
        match &mut self.connection {
            ClientHttpConnection::LegacySse { client, .. } => {
                block_on(client.send(&self.cx, &notification)).map_err(legacy_http_error)?;
            }
            ClientHttpConnection::Modern(_) => {
                return Err(McpError::internal_error(
                    "Modern HTTP proxy connection entered legacy lifecycle acknowledgement",
                ));
            }
        }
        self.legacy_initialized = true;
        Ok(())
    }

    fn request_result(
        &mut self,
        method: &str,
        parameters: serde_json::Value,
    ) -> McpResult<CoreResult> {
        let mut ignore_final_progress = |_| {};
        self.request_result_with_final_progress(method, parameters, &mut ignore_final_progress)
    }

    fn request_result_with_final_progress(
        &mut self,
        method: &str,
        parameters: serde_json::Value,
        on_progress: FinalProgressCallback<'_>,
    ) -> McpResult<CoreResult> {
        if self.binding.era() == ProtocolEra::Legacy2024 {
            self.ensure_legacy_initialized()?;
        }
        let parameters = self.request_parameters(parameters)?;
        let request = CoreRequest::decode(self.binding.era(), method, Some(&parameters)).map_err(
            |error| {
                McpError::invalid_params(format!(
                    "Proxy HTTP request is invalid for the selected upstream era: {error}"
                ))
            },
        )?;
        let request_id = self.next_request_id()?;
        let response = match &mut self.connection {
            ClientHttpConnection::Modern(client) => receive_modern_response(
                client,
                &self.cx,
                method,
                parameters,
                &request_id,
                on_progress,
            )?,
            ClientHttpConnection::LegacySse { client, .. } => {
                let message = JsonRpcMessage::Request(JsonRpcRequest::new(
                    method,
                    Some(parameters),
                    request_id.clone(),
                ));
                block_on(client.send(&self.cx, &message)).map_err(legacy_http_error)?;
                receive_legacy_response(
                    client,
                    &self.cx,
                    &self.client_capabilities,
                    &request_id,
                    &mut self.legacy_retired_request_ids,
                )?
            }
        };
        if let Some(error) = response.error.as_ref() {
            return Err(McpError::internal_error(format!(
                "Proxy HTTP upstream rejected {method}: {} ({})",
                error.message, error.code
            )));
        }
        request.decode_response(&response).map_err(|error| {
            McpError::invalid_request(format!(
                "Proxy HTTP upstream response is invalid for the selected era: {error}"
            ))
        })
    }
}

impl ProxyBackend for ProxyHttpClient {
    fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
        match self.list_tool_catalog()? {
            ProxyToolCatalog::Legacy(tools) => Ok(tools),
            ProxyToolCatalog::Final(_) => Err(McpError::invalid_request(
                "Proxy cannot project a final tools/list catalog to the legacy tool surface",
            )),
        }
    }

    fn list_tool_catalog(&mut self) -> McpResult<ProxyToolCatalog> {
        match self.binding.era() {
            ProtocolEra::Legacy2024 => {
                match self
                    .request_result(fastmcp_protocol::methods::TOOLS_LIST, serde_json::json!({}))?
                {
                    CoreResult::Legacy(LegacyCoreResult::ToolsList(result)) => {
                        Ok(ProxyToolCatalog::Legacy(result.tools))
                    }
                    CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) => {
                        let payload = result.payload;
                        Ok(ProxyToolCatalog::Final(ProxyFinalCatalog::single_page(
                            payload.tools,
                            payload.ttl_ms,
                            payload.cache_scope,
                        )))
                    }
                    _ => Err(unexpected_proxy_result("tools/list")),
                }
            }
            ProtocolEra::Modern2026 => collect_modern_proxy_catalog_pages(
                fastmcp_protocol::methods::TOOLS_LIST,
                |cursor| match self.request_result(
                    fastmcp_protocol::methods::TOOLS_LIST,
                    Self::modern_catalog_parameters(cursor),
                )? {
                    CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) => {
                        let payload = result.payload;
                        Ok((
                            payload.tools,
                            payload.next_cursor,
                            ProxyCatalogCacheHint::new(payload.ttl_ms, payload.cache_scope),
                        ))
                    }
                    CoreResult::Legacy(LegacyCoreResult::ToolsList(_)) => {
                        Err(McpError::invalid_request(
                            "Modern HTTP proxy received a legacy tools/list result",
                        ))
                    }
                    _ => Err(unexpected_proxy_result("tools/list")),
                },
            )
            .map(ProxyToolCatalog::Final),
        }
    }

    fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        match self.list_resource_catalog()? {
            ProxyResourceCatalog::Legacy(resources) => Ok(resources),
            ProxyResourceCatalog::Final(_) => Err(McpError::invalid_request(
                "Proxy cannot project a final resources/list catalog to the legacy resource surface",
            )),
        }
    }

    fn list_resource_catalog(&mut self) -> McpResult<ProxyResourceCatalog> {
        match self.binding.era() {
            ProtocolEra::Legacy2024 => match self.request_result(
                fastmcp_protocol::methods::RESOURCES_LIST,
                serde_json::json!({}),
            )? {
                CoreResult::Legacy(LegacyCoreResult::ResourcesList(result)) => {
                    Ok(ProxyResourceCatalog::Legacy(result.resources))
                }
                CoreResult::Final(FinalCoreResult::ResourcesList { result, .. }) => {
                    let payload = result.payload;
                    Ok(ProxyResourceCatalog::Final(ProxyFinalCatalog::single_page(
                        payload.resources,
                        payload.ttl_ms,
                        payload.cache_scope,
                    )))
                }
                _ => Err(unexpected_proxy_result("resources/list")),
            },
            ProtocolEra::Modern2026 => collect_modern_proxy_catalog_pages(
                fastmcp_protocol::methods::RESOURCES_LIST,
                |cursor| match self.request_result(
                    fastmcp_protocol::methods::RESOURCES_LIST,
                    Self::modern_catalog_parameters(cursor),
                )? {
                    CoreResult::Final(FinalCoreResult::ResourcesList { result, .. }) => {
                        let payload = result.payload;
                        Ok((
                            payload.resources,
                            payload.next_cursor,
                            ProxyCatalogCacheHint::new(payload.ttl_ms, payload.cache_scope),
                        ))
                    }
                    CoreResult::Legacy(LegacyCoreResult::ResourcesList(_)) => {
                        Err(McpError::invalid_request(
                            "Modern HTTP proxy received a legacy resources/list result",
                        ))
                    }
                    _ => Err(unexpected_proxy_result("resources/list")),
                },
            )
            .map(ProxyResourceCatalog::Final),
        }
    }

    fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
        match self.list_resource_template_catalog()? {
            ProxyResourceTemplateCatalog::Legacy(templates) => Ok(templates),
            ProxyResourceTemplateCatalog::Final(_) => Err(McpError::invalid_request(
                "Proxy cannot project a final resources/templates/list catalog to the legacy resource-template surface",
            )),
        }
    }

    fn list_resource_template_catalog(&mut self) -> McpResult<ProxyResourceTemplateCatalog> {
        match self.binding.era() {
            ProtocolEra::Legacy2024 => match self.request_result(
                fastmcp_protocol::methods::RESOURCES_TEMPLATES_LIST,
                serde_json::json!({}),
            )? {
                CoreResult::Legacy(LegacyCoreResult::ResourceTemplatesList(result)) => Ok(
                    ProxyResourceTemplateCatalog::Legacy(result.resource_templates),
                ),
                CoreResult::Final(FinalCoreResult::ResourceTemplatesList { result, .. }) => {
                    let payload = result.payload;
                    Ok(ProxyResourceTemplateCatalog::Final(
                        ProxyFinalCatalog::single_page(
                            payload.resource_templates,
                            payload.ttl_ms,
                            payload.cache_scope,
                        ),
                    ))
                }
                _ => Err(unexpected_proxy_result("resources/templates/list")),
            },
            ProtocolEra::Modern2026 => collect_modern_proxy_catalog_pages(
                fastmcp_protocol::methods::RESOURCES_TEMPLATES_LIST,
                |cursor| match self.request_result(
                    fastmcp_protocol::methods::RESOURCES_TEMPLATES_LIST,
                    Self::modern_catalog_parameters(cursor),
                )? {
                    CoreResult::Final(FinalCoreResult::ResourceTemplatesList {
                        result, ..
                    }) => {
                        let payload = result.payload;
                        Ok((
                            payload.resource_templates,
                            payload.next_cursor,
                            ProxyCatalogCacheHint::new(payload.ttl_ms, payload.cache_scope),
                        ))
                    }
                    CoreResult::Legacy(LegacyCoreResult::ResourceTemplatesList(_)) => {
                        Err(McpError::invalid_request(
                            "Modern HTTP proxy received a legacy resources/templates/list result",
                        ))
                    }
                    _ => Err(unexpected_proxy_result("resources/templates/list")),
                },
            )
            .map(ProxyResourceTemplateCatalog::Final),
        }
    }

    fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
        match self.list_prompt_catalog()? {
            ProxyPromptCatalog::Legacy(prompts) => Ok(prompts),
            ProxyPromptCatalog::Final(_) => Err(McpError::invalid_request(
                "Proxy cannot project a final prompts/list catalog to the legacy prompt surface",
            )),
        }
    }

    fn list_prompt_catalog(&mut self) -> McpResult<ProxyPromptCatalog> {
        match self.binding.era() {
            ProtocolEra::Legacy2024 => match self.request_result(
                fastmcp_protocol::methods::PROMPTS_LIST,
                serde_json::json!({}),
            )? {
                CoreResult::Legacy(LegacyCoreResult::PromptsList(result)) => {
                    Ok(ProxyPromptCatalog::Legacy(result.prompts))
                }
                CoreResult::Final(FinalCoreResult::PromptsList { result, .. }) => {
                    let payload = result.payload;
                    Ok(ProxyPromptCatalog::Final(ProxyFinalCatalog::single_page(
                        payload.prompts,
                        payload.ttl_ms,
                        payload.cache_scope,
                    )))
                }
                _ => Err(unexpected_proxy_result("prompts/list")),
            },
            ProtocolEra::Modern2026 => collect_modern_proxy_catalog_pages(
                fastmcp_protocol::methods::PROMPTS_LIST,
                |cursor| match self.request_result(
                    fastmcp_protocol::methods::PROMPTS_LIST,
                    Self::modern_catalog_parameters(cursor),
                )? {
                    CoreResult::Final(FinalCoreResult::PromptsList { result, .. }) => {
                        let payload = result.payload;
                        Ok((
                            payload.prompts,
                            payload.next_cursor,
                            ProxyCatalogCacheHint::new(payload.ttl_ms, payload.cache_scope),
                        ))
                    }
                    CoreResult::Legacy(LegacyCoreResult::PromptsList(_)) => {
                        Err(McpError::invalid_request(
                            "Modern HTTP proxy received a legacy prompts/list result",
                        ))
                    }
                    _ => Err(unexpected_proxy_result("prompts/list")),
                },
            )
            .map(ProxyPromptCatalog::Final),
        }
    }

    fn call_tool(&mut self, name: &str, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        match self.call_tool_result(name, arguments)? {
            CoreResult::Legacy(LegacyCoreResult::ToolsCall(result)) => {
                legacy_tool_result_to_handler(result)
            }
            CoreResult::Final(FinalCoreResult::ToolsCall { .. }) => Err(McpError::invalid_request(
                "Proxy cannot project a final tools/call result to the legacy handler surface",
            )),
            _ => Err(unexpected_proxy_result("tools/call")),
        }
    }

    fn call_tool_with_progress(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
        _on_progress: ProgressCallback<'_>,
    ) -> McpResult<Vec<Content>> {
        self.call_tool(name, arguments)
    }

    fn read_resource(&mut self, uri: &str) -> McpResult<Vec<ResourceContent>> {
        match self.read_resource_result(uri)? {
            CoreResult::Legacy(LegacyCoreResult::ResourcesRead(result)) => {
                legacy_resource_result_to_handler(result)
            }
            CoreResult::Final(FinalCoreResult::ResourcesRead { .. }) => {
                Err(McpError::invalid_request(
                    "Proxy cannot project a final resources/read result to the legacy handler surface",
                ))
            }
            _ => Err(unexpected_proxy_result("resources/read")),
        }
    }

    fn get_prompt(
        &mut self,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        match self.get_prompt_result(name, arguments)? {
            CoreResult::Legacy(LegacyCoreResult::PromptsGet(result)) => {
                legacy_prompt_result_to_handler(result)
            }
            CoreResult::Final(FinalCoreResult::PromptsGet { .. }) => {
                Err(McpError::invalid_request(
                    "Proxy cannot project a final prompts/get result to the legacy handler surface",
                ))
            }
            _ => Err(unexpected_proxy_result("prompts/get")),
        }
    }

    fn call_tool_result(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<CoreResult> {
        self.request_result(
            fastmcp_protocol::methods::TOOLS_CALL,
            serde_json::json!({"name": name, "arguments": arguments}),
        )
    }

    fn call_tool_result_with_final_progress(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
        on_progress: FinalProgressCallback<'_>,
    ) -> McpResult<CoreResult> {
        self.request_result_with_final_progress(
            fastmcp_protocol::methods::TOOLS_CALL,
            serde_json::json!({"name": name, "arguments": arguments}),
            on_progress,
        )
    }

    fn read_resource_result(&mut self, uri: &str) -> McpResult<CoreResult> {
        self.request_result(
            fastmcp_protocol::methods::RESOURCES_READ,
            serde_json::json!({"uri": uri}),
        )
    }

    fn get_prompt_result(
        &mut self,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<CoreResult> {
        self.request_result(
            fastmcp_protocol::methods::PROMPTS_GET,
            serde_json::json!({"name": name, "arguments": arguments}),
        )
    }
}

fn receive_modern_response(
    client: &ModernHttpClient,
    cx: &Cx,
    method: &str,
    parameters: serde_json::Value,
    request_id: &RequestId,
    on_progress: FinalProgressCallback<'_>,
) -> McpResult<JsonRpcResponse> {
    let response = block_on(client.request(cx, method, parameters, Some(request_id.clone())))
        .map_err(|error| {
            McpError::internal_error(format!("Proxy HTTP modern request failed: {error}"))
        })?;
    match response.metadata().kind() {
        ModernHttpResponseKind::Json => {
            let body = block_on(response.read_to_end(cx, ProxyHttpClient::MAX_RESPONSE_BYTES))
                .map_err(|error| {
                    McpError::internal_error(format!(
                        "Proxy HTTP modern JSON response could not be read: {error}"
                    ))
                })?;
            response_for_request(
                decode_strict_jsonrpc_message(&body, ProxyHttpClient::MAX_RESPONSE_BYTES).map_err(
                    |_| McpError::invalid_request("Proxy HTTP modern response was not JSON-RPC"),
                )?,
                request_id,
            )
        }
        ModernHttpResponseKind::Sse => {
            let mut stream = response
                .into_sse_stream(ProxyHttpClient::sse_limits())
                .map_err(|error| {
                    McpError::internal_error(format!(
                        "Proxy HTTP modern SSE response could not be opened: {error}"
                    ))
                })?;
            loop {
                let event = block_on(stream.next_event(cx)).map_err(|error| {
                    McpError::internal_error(format!(
                        "Proxy HTTP modern SSE response could not be read: {error}"
                    ))
                })?;
                let Some(event) = event else {
                    return Err(McpError::invalid_request(
                        "Proxy HTTP modern SSE response ended before its correlated result",
                    ));
                };
                let message = decode_strict_jsonrpc_message(
                    event.as_bytes(),
                    ProxyHttpClient::MAX_RESPONSE_BYTES,
                )
                .map_err(|_| {
                    McpError::invalid_request("Proxy HTTP modern SSE event was not JSON-RPC")
                })?;
                if let JsonRpcMessage::Request(request) = &message
                    && request.is_notification()
                {
                    forward_modern_progress_notification(
                        event.as_bytes(),
                        request,
                        &mut *on_progress,
                    )?;
                    continue;
                }
                return response_for_request(message, request_id);
            }
        }
        ModernHttpResponseKind::EmptyAcknowledgement => Err(McpError::invalid_request(
            "Proxy HTTP modern request received a notification acknowledgement where a correlated response was required",
        )),
        ModernHttpResponseKind::HttpFailure => Err(McpError::invalid_request(
            "Proxy HTTP modern request received an unsuccessful HTTP response",
        )),
    }
}

/// Decodes a modern upstream server notification while retaining its original
/// `params` slice. This matters for progress notifications: their exact number
/// spelling is part of the final protocol model and is lost if the frame is
/// first reduced to a `serde_json::Value`.
fn decode_modern_server_notification(
    raw_frame: &[u8],
    request: &JsonRpcRequest,
) -> McpResult<ServerNotification> {
    #[derive(Deserialize)]
    struct RawNotificationParams<'a> {
        #[serde(borrow)]
        params: Option<&'a RawValue>,
    }

    let raw = serde_json::from_slice::<RawNotificationParams<'_>>(raw_frame).map_err(|_| {
        McpError::invalid_request("Proxy HTTP modern notification was not a JSON-RPC object")
    })?;
    let raw_params = raw.params.map(RawValue::get).unwrap_or("null");
    ServerNotification::decode_with_raw_params(request, raw_params)
        .map_err(|_| McpError::invalid_request("Proxy HTTP modern server notification was invalid"))
}

/// Decodes and forwards one exact-final upstream progress notification.
///
/// This boundary deliberately takes the raw SSE frame and a final-only
/// callback. It therefore cannot silently route modern progress through the
/// legacy floating-point callback surface.
fn forward_modern_progress_notification(
    raw_frame: &[u8],
    request: &JsonRpcRequest,
    on_progress: FinalProgressCallback<'_>,
) -> McpResult<()> {
    let notification = decode_modern_server_notification(raw_frame, request)?;
    if let ServerNotification::Progress(params) = notification {
        on_progress(params);
    }
    Ok(())
}

/// Maximum interleaved control frames accepted while one exact-2024 request
/// waits for its correlated upstream response.
const MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES: usize = 64;

/// Maximum cancelled request IDs retained to discard a late response before a
/// later request consumes the shared exact-2024 SSE stream.
const MAX_RETIRED_LEGACY_REQUEST_IDS: usize = 64;

fn receive_legacy_response(
    client: &mut LegacySseHttpClient,
    cx: &Cx,
    client_capabilities: &ClientCapabilities,
    request_id: &RequestId,
    retired_request_ids: &mut VecDeque<RequestId>,
) -> McpResult<JsonRpcResponse> {
    let mut interleaved_control_frames = 0_usize;
    loop {
        let message = block_on(client.next_message(cx)).map_err(legacy_http_error)?;
        let Some(message) = message else {
            return Err(McpError::invalid_request(
                "Proxy HTTP legacy SSE stream ended before its correlated result",
            ));
        };
        match message {
            JsonRpcMessage::Request(request) if request.is_notification() => {
                admit_legacy_interleaved_control_frame(&mut interleaved_control_frames)?;
                if request.method == fastmcp_protocol::methods::NOTIFICATIONS_CANCELLED {
                    let cancellation = CancellationWireMessage::decode(
                        ProtocolEra::Legacy2024,
                        CancellationSender::Server,
                        &request,
                    )
                    .map_err(|_| {
                        McpError::invalid_request(
                            "Proxy HTTP legacy cancellation notification was invalid",
                        )
                    })?;
                    let CancellationWireMessage::Legacy2024 { params, .. } = cancellation else {
                        return Err(McpError::invalid_request(
                            "Proxy HTTP legacy cancellation selected a non-legacy payload",
                        ));
                    };
                    if params.request_id.correlates_with(request_id) {
                        retire_legacy_request_id(retired_request_ids, request_id)?;
                        return Err(McpError::request_cancelled());
                    }
                }
            }
            JsonRpcMessage::Request(request) => {
                admit_legacy_interleaved_control_frame(&mut interleaved_control_frames)?;
                let Some(reply) = legacy_reverse_request_reply(&request, client_capabilities)
                else {
                    return Err(McpError::invalid_request(
                        "Proxy HTTP legacy upstream request omitted its JSON-RPC ID",
                    ));
                };
                block_on(client.send(cx, &reply)).map_err(legacy_http_error)?;
            }
            JsonRpcMessage::Response(response) => {
                if response.id.as_ref().is_some_and(|response_id| {
                    consume_retired_legacy_response(retired_request_ids, response_id)
                }) {
                    continue;
                }
                return response_for_request(JsonRpcMessage::Response(response), request_id);
            }
        }
    }
}

fn admit_legacy_interleaved_control_frame(count: &mut usize) -> McpResult<()> {
    if *count >= MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES {
        return Err(McpError::invalid_request(
            "Proxy HTTP legacy request exceeded its interleaved control-frame bound",
        ));
    }
    *count = count.checked_add(1).ok_or_else(|| {
        McpError::invalid_request("Proxy HTTP legacy interleaved control frame count overflowed")
    })?;
    Ok(())
}

fn retire_legacy_request_id(
    retired_request_ids: &mut VecDeque<RequestId>,
    request_id: &RequestId,
) -> McpResult<()> {
    if retired_request_ids
        .iter()
        .any(|retired| retired.correlates_with(request_id))
    {
        return Ok(());
    }
    if retired_request_ids.len() >= MAX_RETIRED_LEGACY_REQUEST_IDS {
        return Err(McpError::invalid_request(
            "Proxy HTTP legacy retired-response capacity exceeded",
        ));
    }
    retired_request_ids.push_back(request_id.clone());
    Ok(())
}

fn consume_retired_legacy_response(
    retired_request_ids: &mut VecDeque<RequestId>,
    response_id: &RequestId,
) -> bool {
    let Some(index) = retired_request_ids
        .iter()
        .position(|retired| retired.correlates_with(response_id))
    else {
        return false;
    };
    retired_request_ids.remove(index);
    true
}

fn legacy_reverse_request_reply(
    request: &JsonRpcRequest,
    client_capabilities: &ClientCapabilities,
) -> Option<JsonRpcMessage> {
    let request_id = request.id.clone()?;
    let result = match request.method.as_str() {
        fastmcp_protocol::methods::SAMPLING_CREATE_MESSAGE
            if client_capabilities.sampling.is_some() =>
        {
            decode_legacy_reverse_request_params::<CreateMessageParams>(request).and_then(|_| {
                Err(McpError::internal_error(
                    "Proxy HTTP legacy sampling callback is unavailable",
                ))
            })
        }
        fastmcp_protocol::methods::ROOTS_LIST if client_capabilities.roots.is_some() => {
            decode_legacy_reverse_request_params::<ListRootsParams>(request)
                .map(|_| ListRootsResult::empty())
        }
        "elicitation/create" => Err(McpError::method_not_found(&request.method)),
        _ => Err(McpError::method_not_found(&request.method)),
    };
    Some(legacy_reverse_request_response(request_id, result))
}

fn decode_legacy_reverse_request_params<T>(request: &JsonRpcRequest) -> McpResult<T>
where
    T: serde::de::DeserializeOwned,
{
    let parameters = request
        .params
        .clone()
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
    serde_json::from_value(parameters)
        .map_err(|_| McpError::invalid_params("Invalid legacy reverse request parameters"))
}

fn legacy_reverse_request_response<T>(request_id: RequestId, result: McpResult<T>) -> JsonRpcMessage
where
    T: serde::Serialize,
{
    match result.and_then(|result| {
        serde_json::to_value(result).map_err(|_| {
            McpError::internal_error("Proxy HTTP legacy reverse response could not be encoded")
        })
    }) {
        Ok(result) => JsonRpcMessage::Response(JsonRpcResponse::success(request_id, result)),
        Err(error) => {
            JsonRpcMessage::Response(JsonRpcResponse::error(Some(request_id), error.into()))
        }
    }
}

fn response_for_request(
    message: JsonRpcMessage,
    request_id: &RequestId,
) -> McpResult<JsonRpcResponse> {
    let JsonRpcMessage::Response(response) = message else {
        return Err(McpError::invalid_request(
            "Proxy HTTP upstream sent a request while its response was required",
        ));
    };
    if response.id.as_ref() != Some(request_id) {
        return Err(McpError::invalid_request(
            "Proxy HTTP upstream response ID does not match its request",
        ));
    }
    Ok(response)
}

fn legacy_http_error(error: impl std::fmt::Display) -> McpError {
    McpError::internal_error(format!("Proxy HTTP legacy request failed: {error}"))
}

fn unexpected_proxy_result(method: &str) -> McpError {
    McpError::invalid_request(format!(
        "Proxy HTTP upstream returned a result for another method instead of {method}"
    ))
}

fn legacy_icon(icons: Option<Vec<RawIcon>>) -> Option<fastmcp_protocol::Icon> {
    icons
        .and_then(|icons| icons.into_iter().next())
        .map(|icon| fastmcp_protocol::Icon {
            src: Some(icon.src.as_str().to_owned()),
            mime_type: icon.mime_type,
            sizes: icon.sizes.map(|sizes| sizes.join(" ")),
        })
}

/// Supplies the mandatory legacy handler shape for a final proxy tool.
///
/// This is intentionally not a catalog conversion: modern registration reads
/// the exact `FinalTool` retained by [`ProxyToolHandler`]. The fallback exists
/// solely for the legacy base method on [`ToolHandler`].
fn final_tool_legacy_fallback(tool: &fastmcp_protocol::FinalTool) -> Tool {
    Tool {
        name: tool.name.clone(),
        description: tool.description.clone(),
        input_schema: tool.input_schema.clone(),
        output_schema: tool.output_schema.clone(),
        icon: legacy_icon(tool.icons.clone()),
        version: None,
        tags: Vec::new(),
        annotations: tool
            .annotations
            .as_ref()
            .map(|annotations| ToolAnnotations {
                destructive: annotations.destructive,
                idempotent: annotations.idempotent,
                read_only: annotations.read_only,
                open_world_hint: annotations.open_world_hint,
            }),
    }
}

fn serialized_cache_identity<T: serde::Serialize>(value: &T, member: &str) -> McpResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|error| {
        McpError::internal_error(format!(
            "Proxy HTTP cache identity could not encode {member}: {error}"
        ))
    })
}

/// Cache of immutable selections for independently configured proxy upstreams.
///
/// A cache entry is never keyed by an origin alone. Route, complete transport
/// identity, policy (inside the HTTP bundle), adapter receipt identity, and
/// configuration generation all participate in its identity.
#[derive(Debug, Default)]
pub struct ProxyUpstreamBindingRegistry {
    stdio: HashMap<StdioBindingKey, ProxyUpstreamBinding>,
    live_stdio: HashMap<LiveStdioBindingKey, ProxyClient>,
    http: HashMap<HttpBindingKey, ProxyUpstreamBinding>,
    http_eras: HttpEraCache,
    live_http: HashMap<LiveHttpBindingKey, ProxyClient>,
}

impl ProxyUpstreamBindingRegistry {
    /// Invalidates cached selections for one exact configured upstream binding.
    ///
    /// The route, transport, adapter receipt, and complete immutable binding
    /// (including its configuration generation) must all match. Other
    /// generations and sibling cache keys remain cacheable. Any selected HTTP
    /// era associated with the removed exact binding is invalidated with its
    /// full endpoint bundle key as well. Live clients have no adapter receipt
    /// in their key and must be evicted through
    /// [`Self::invalidate_live_cached_binding`] instead.
    pub fn invalidate_cached_binding(
        &mut self,
        route_identity: &str,
        transport_identity: &str,
        adapter_receipt_identity: &str,
        binding: ProxyUpstreamBinding,
    ) -> McpResult<usize> {
        validate_binding_key(route_identity, transport_identity, adapter_receipt_identity)?;

        let mut removed = 0;
        self.stdio.retain(|key, cached| {
            let matches = key.route_identity == route_identity
                && key.transport_identity == transport_identity
                && key.adapter_receipt_identity == adapter_receipt_identity
                && key.configuration_generation == binding.configuration_generation
                && *cached == binding;
            if matches {
                removed += 1;
            }
            !matches
        });
        let mut http_era_keys = HashSet::new();
        self.http.retain(|key, cached| {
            let matches = key.route_identity == route_identity
                && key.transport_identity == transport_identity
                && key.adapter_receipt_identity == adapter_receipt_identity
                && key.configuration_generation == binding.configuration_generation
                && *cached == binding;
            if matches {
                http_era_keys.insert(key.bundle.clone());
                removed += 1;
            }
            !matches
        });
        for key in http_era_keys {
            self.http_eras.invalidate(&key);
        }
        Ok(removed)
    }

    /// Invalidates live upstream clients for one route-local binding generation.
    ///
    /// Live client keys deliberately omit the adapter receipt, but include the
    /// immutable route, transport, policy, and configuration generation. The
    /// retained client binding is checked as well, so another era or policy is
    /// never evicted by this generation-scoped operation.
    pub fn invalidate_live_cached_binding(
        &mut self,
        route_identity: &str,
        transport_identity: &str,
        binding: ProxyUpstreamBinding,
    ) -> McpResult<usize> {
        if route_identity.is_empty() || transport_identity.is_empty() {
            return Err(McpError::invalid_params(
                "Upstream route and transport identities must be non-empty",
            ));
        }

        let mut removed = 0;
        self.live_stdio.retain(|key, cached| {
            let matches = key.route_identity == route_identity
                && key.transport_identity == transport_identity
                && key.policy == binding.policy
                && key.configuration_generation == binding.configuration_generation
                && cached.upstream_binding() == Some(binding);
            if matches {
                removed += 1;
            }
            !matches
        });
        self.live_http.retain(|key, cached| {
            let matches = key.route_identity == route_identity
                && key.transport_identity == transport_identity
                && key.configuration_generation == binding.configuration_generation
                && cached.upstream_binding() == Some(binding);
            if matches {
                removed += 1;
            }
            !matches
        });
        Ok(removed)
    }

    /// Opens a real stdio upstream from an immutable client protocol plan.
    ///
    /// The binding is derived from the connected client's selected era, never
    /// from caller-provided opening-frame assumptions. `Auto` therefore uses
    /// the client's modern-first discovery and only observes the client's
    /// narrowly authorized fallback behavior. A cache entry is inserted only
    /// after both connection and exact selected-era admission succeed. Later
    /// establishments for the same immutable upstream reuse that live client,
    /// rather than allowing a caller-provided classification or a fresh
    /// negotiation to alter the pinned era.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_stdio_with_protocol_plan(
        &mut self,
        route_identity: &str,
        transport_identity: &str,
        configuration_generation: u64,
        command: &str,
        args: &[&str],
        protocol_plan: ClientProtocolPlan,
        cx: Cx,
    ) -> McpResult<ProxyClient> {
        if route_identity.is_empty() || transport_identity.is_empty() {
            return Err(McpError::invalid_params(
                "Upstream route and transport identities must be non-empty",
            ));
        }
        if protocol_plan.http_endpoints().is_some() {
            return Err(McpError::invalid_params(
                "A stdio proxy upstream requires a stdio client protocol plan",
            ));
        }

        let key = LiveStdioBindingKey {
            route_identity: route_identity.to_owned(),
            transport_identity: transport_identity.to_owned(),
            policy: protocol_plan.policy(),
            configuration_generation,
        };
        if let Some(existing) = self.live_stdio.get(&key) {
            return Ok(existing.clone());
        }

        let client = Client::stdio_with_protocol_plan_with_cx(command, args, protocol_plan, cx)?;
        let binding = binding_from_live_stdio_client(&client, configuration_generation)?;

        let upstream_protocol_version = client.protocol_version().to_owned();
        let proxy = ProxyClient::from_backend_with_upstream_binding(
            client,
            binding,
            &upstream_protocol_version,
        )?;
        self.live_stdio.insert(key, proxy.clone());
        Ok(proxy)
    }

    /// Opens and caches one real HTTP upstream client from an immutable plan.
    ///
    /// `Auto` delegates selection to the shipped modern HTTP client: a typed
    /// modern discovery response selects only MCP 2026-07-28, and only that
    /// client's narrowly recognized disposable-probe refusal can open the
    /// exact configured legacy SSE GET plus advertised-POST route. The live
    /// selected client is cached per complete backend identity, so another
    /// request for that same backend cannot re-probe or switch eras.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_http_with_protocol_plan(
        &mut self,
        route_identity: &str,
        transport_identity: &str,
        configuration_generation: u64,
        protocol_plan: ClientProtocolPlan,
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        cx: Cx,
    ) -> McpResult<ProxyClient> {
        if route_identity.is_empty() || transport_identity.is_empty() {
            return Err(McpError::invalid_params(
                "Upstream route and transport identities must be non-empty",
            ));
        }
        let bundle = protocol_plan.http_endpoints().ok_or_else(|| {
            McpError::invalid_params("An HTTP proxy upstream requires an HTTP client protocol plan")
        })?;
        let key = LiveHttpBindingKey {
            route_identity: route_identity.to_owned(),
            transport_identity: transport_identity.to_owned(),
            configuration_generation,
            bundle: bundle.key(),
            client_info_wire: serialized_cache_identity(&client_info, "clientInfo")?,
            client_capabilities_wire: serialized_cache_identity(
                &client_capabilities,
                "clientCapabilities",
            )?,
        };
        if let Some(existing) = self.live_http.get(&key) {
            return Ok(existing.clone());
        }

        let connection = block_on(ClientHttpConnection::connect(
            &cx,
            protocol_plan.clone(),
            client_info.clone(),
            client_capabilities.clone(),
        ))
        .map_err(|error| {
            McpError::internal_error(format!("HTTP proxy upstream connect failed: {error}"))
        })?;
        let binding = binding_from_live_http_connection(
            &connection,
            protocol_plan.policy(),
            configuration_generation,
        )?;
        let backend =
            ProxyHttpClient::new(binding, connection, cx, client_info, client_capabilities);
        let proxy = ProxyClient::from_backend_with_upstream_binding(
            backend,
            binding,
            binding.era().version().as_str(),
        )?;
        self.live_http.insert(key, proxy.clone());
        Ok(proxy)
    }

    /// Binds one stdio upstream using the exact two-era opening classifier.
    ///
    /// `adapter_receipt_identity` is an opaque identity supplied by the
    /// installed upstream adapter. It is part of the cache key and must be
    /// non-empty; this method neither fabricates a legacy receipt nor retries
    /// selection under another policy.
    pub fn bind_stdio(
        &mut self,
        route_identity: &str,
        transport_identity: &str,
        adapter_receipt_identity: &str,
        configuration_generation: u64,
        policy: ProtocolPolicy,
        opening: StdioOpeningFrame,
    ) -> McpResult<ProxyUpstreamBinding> {
        let key = StdioBindingKey {
            route_identity: route_identity.to_owned(),
            transport_identity: transport_identity.to_owned(),
            adapter_receipt_identity: adapter_receipt_identity.to_owned(),
            policy,
            configuration_generation,
        };
        validate_binding_key(
            &key.route_identity,
            &key.transport_identity,
            &key.adapter_receipt_identity,
        )?;
        if let Some(binding) = self.stdio.get(&key) {
            return Ok(*binding);
        }

        let mut classifier = StdioEraClassifier::new(policy);
        let binding = match classifier.classify_opening(opening) {
            StdioEraDecision::Selected {
                era: ProtocolEra::Modern2026,
                modern_version: Some(ModernVersionSupport::Supported),
            } => ProxyUpstreamBinding {
                era: ProtocolEra::Modern2026,
                adapter: ProxyUpstreamAdapter::ModernStdio,
                policy,
                configuration_generation,
            },
            StdioEraDecision::Selected {
                era: ProtocolEra::Legacy2024,
                modern_version: None,
            } => ProxyUpstreamBinding {
                era: ProtocolEra::Legacy2024,
                adapter: ProxyUpstreamAdapter::LegacyStdio,
                policy,
                configuration_generation,
            },
            _ => {
                return Err(McpError::invalid_request(
                    "Upstream stdio opening does not select an exact permitted MCP era",
                ));
            }
        };
        self.stdio.insert(key, binding);
        Ok(binding)
    }

    /// Binds one HTTP upstream through its configured modern or legacy routes.
    ///
    /// Modern bindings use only the modern request/response route; legacy
    /// bindings use only the exact-2024 SSE plus advertised-POST route chosen
    /// by the immutable endpoint bundle.
    pub fn bind_http(
        &mut self,
        route_identity: &str,
        transport_identity: &str,
        adapter_receipt_identity: &str,
        configuration_generation: u64,
        policy: ProtocolPolicy,
        modern_post: Option<CanonicalHttpUrl>,
        legacy_sse: Option<CanonicalHttpUrl>,
        legacy_message_post: Option<CanonicalHttpUrl>,
        credential_partition: String,
        security_partition: String,
        transport_profile: String,
        policy_generation: u64,
        legacy_receipt_generation: u64,
        probe: HttpModernProbe,
    ) -> McpResult<ProxyUpstreamBinding> {
        validate_binding_key(route_identity, transport_identity, adapter_receipt_identity)?;
        let bundle = HttpEndpointBundle::new(
            policy,
            modern_post,
            legacy_sse,
            legacy_message_post,
            credential_partition,
            security_partition,
            transport_profile,
            policy_generation,
            configuration_generation,
            legacy_receipt_generation,
        )
        .map_err(|error| McpError::invalid_params(error.to_string()))?;
        let key = HttpBindingKey {
            route_identity: route_identity.to_owned(),
            transport_identity: transport_identity.to_owned(),
            adapter_receipt_identity: adapter_receipt_identity.to_owned(),
            configuration_generation,
            bundle: bundle.key(),
        };
        if let Some(binding) = self.http.get(&key) {
            return Ok(*binding);
        }
        let era = match self.http_eras.classify_or_cached(&bundle, probe) {
            HttpEraDecision::Selected(era) => era,
            HttpEraDecision::LegacySseFallbackAuthorized => {
                return Err(McpError::invalid_request(
                    "Upstream HTTP probe authorizes legacy SSE observation but cannot select an era before endpoint validation",
                ));
            }
            HttpEraDecision::RejectedWithoutLegacyFallback => {
                return Err(McpError::invalid_request(
                    "Upstream HTTP probe cannot select an exact permitted MCP era",
                ));
            }
        };
        let adapter = match era {
            ProtocolEra::Modern2026 => ProxyUpstreamAdapter::ModernHttp,
            ProtocolEra::Legacy2024 => ProxyUpstreamAdapter::LegacyHttpSse,
        };
        let binding = ProxyUpstreamBinding {
            era,
            adapter,
            policy,
            configuration_generation,
        };
        self.http.insert(key, binding);
        Ok(binding)
    }
}

fn validate_binding_key(
    route_identity: &str,
    transport_identity: &str,
    adapter_receipt_identity: &str,
) -> McpResult<()> {
    if route_identity.is_empty()
        || transport_identity.is_empty()
        || adapter_receipt_identity.is_empty()
    {
        return Err(McpError::invalid_params(
            "Upstream route, transport, and adapter receipt identities must be non-empty",
        ));
    }
    Ok(())
}

fn binding_from_live_stdio_client(
    client: &Client,
    configuration_generation: u64,
) -> McpResult<ProxyUpstreamBinding> {
    let policy = client.protocol_policy();
    let era = client.selected_protocol_era().ok_or_else(|| {
        McpError::internal_error(
            "Connected upstream client did not select a supported protocol era",
        )
    })?;
    match (policy, era) {
        (ProtocolPolicy::ModernOnly, ProtocolEra::Modern2026)
        | (ProtocolPolicy::LegacyOnly, ProtocolEra::Legacy2024)
        | (ProtocolPolicy::Auto, ProtocolEra::Modern2026 | ProtocolEra::Legacy2024) => {}
        _ => {
            return Err(McpError::invalid_request(
                "Connected upstream era does not satisfy its immutable protocol policy",
            ));
        }
    }

    let binding = ProxyUpstreamBinding {
        era,
        adapter: match era {
            ProtocolEra::Modern2026 => ProxyUpstreamAdapter::ModernStdio,
            ProtocolEra::Legacy2024 => ProxyUpstreamAdapter::LegacyStdio,
        },
        policy,
        configuration_generation,
    };
    binding.admit_upstream_protocol_version(client.protocol_version())?;
    Ok(binding)
}

fn binding_from_live_http_connection(
    connection: &ClientHttpConnection,
    policy: ProtocolPolicy,
    configuration_generation: u64,
) -> McpResult<ProxyUpstreamBinding> {
    let era = connection.selected_protocol_era();
    match (policy, era) {
        (ProtocolPolicy::ModernOnly, ProtocolEra::Modern2026)
        | (ProtocolPolicy::LegacyOnly, ProtocolEra::Legacy2024)
        | (ProtocolPolicy::Auto, ProtocolEra::Modern2026 | ProtocolEra::Legacy2024) => {}
        _ => {
            return Err(McpError::invalid_request(
                "Connected HTTP upstream era does not satisfy its immutable protocol policy",
            ));
        }
    }

    let binding = ProxyUpstreamBinding {
        era,
        adapter: match era {
            ProtocolEra::Modern2026 => ProxyUpstreamAdapter::ModernHttp,
            ProtocolEra::Legacy2024 => ProxyUpstreamAdapter::LegacyHttpSse,
        },
        policy,
        configuration_generation,
    };
    binding.admit_upstream_protocol_version(era.version().as_str())?;
    Ok(binding)
}

impl ProxyClient {
    /// Creates an independent cache for immutable upstream era selections.
    #[must_use]
    pub fn upstream_binding_registry() -> ProxyUpstreamBindingRegistry {
        ProxyUpstreamBindingRegistry::default()
    }
    /// Creates a proxy client from an MCP client.
    #[must_use]
    pub fn from_client(client: Client) -> Self {
        Self::from_backend(client)
    }

    /// Creates a proxy client from a backend implementation.
    #[must_use]
    pub fn from_backend<B: ProxyBackend + 'static>(backend: B) -> Self {
        Self {
            inner: Arc::new(Mutex::new(backend)),
            upstream_binding: None,
        }
    }

    /// Creates a proxy client for one already-selected upstream route.
    ///
    /// The exact upstream version is admitted before the backend can enter an
    /// ordinary proxy handler. The immutable binding remains local to this
    /// client, so one legacy route cannot alter an unrelated modern route.
    pub fn from_backend_with_upstream_binding<B: ProxyBackend + 'static>(
        backend: B,
        binding: ProxyUpstreamBinding,
        upstream_protocol_version: &str,
    ) -> McpResult<Self> {
        binding.admit_upstream_protocol_version(upstream_protocol_version)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(backend)),
            upstream_binding: Some(binding),
        })
    }

    /// Returns the immutable binding installed for this upstream, if any.
    #[must_use]
    pub const fn upstream_binding(&self) -> Option<ProxyUpstreamBinding> {
        self.upstream_binding
    }

    /// Fetches a catalog by querying the backend.
    pub fn catalog(&self) -> McpResult<ProxyCatalog> {
        let catalog = self.with_backend(|backend| ProxyCatalog::from_backend(backend))?;
        self.admit_catalog(&catalog)?;
        Ok(catalog)
    }

    /// Discovers every upstream catalog without asking the caller to choose an era.
    ///
    /// The backend performs its normal initialization/negotiation first. Final
    /// catalogs remain in their exact final models, including display metadata,
    /// annotations, icon collections, and open metadata; legacy catalogs stay
    /// legacy. A mixed-era response is rejected before any caller can compose
    /// it into a downstream route.
    pub fn catalog_typed(&self) -> McpResult<ProxyTypedCatalog> {
        let catalog = self.with_backend(|backend| {
            Ok(ProxyTypedCatalog {
                tools: backend.list_tool_catalog()?,
                resources: backend.list_resource_catalog()?,
                resource_templates: backend.list_resource_template_catalog()?,
                prompts: backend.list_prompt_catalog()?,
            })
        })?;
        let era = catalog.era()?;
        if let Some(binding) = self.upstream_binding
            && binding.era() != era
        {
            return Err(McpError::invalid_request(
                "Proxy typed catalog era contradicts the immutable route binding",
            ));
        }
        Ok(catalog)
    }

    /// Admits a catalog only when it agrees with this client's immutable route
    /// binding. This also protects builder callers that supply a catalog
    /// directly rather than obtaining it through [`Self::catalog`].
    pub(crate) fn admit_catalog(&self, catalog: &ProxyCatalog) -> McpResult<()> {
        catalog.admit_catalog_shape()?;
        if let Some(binding) = self.upstream_binding {
            catalog.admit_upstream_binding(binding)?;
        }
        Ok(())
    }

    fn with_backend<F, R>(&self, f: F) -> McpResult<R>
    where
        F: FnOnce(&mut dyn ProxyBackend) -> McpResult<R>,
    {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| McpError::internal_error("Proxy backend lock poisoned"))?;
        f(&mut *guard)
    }

    pub fn call_tool(
        &self,
        ctx: &McpContext,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<Vec<Content>> {
        ctx.checkpoint()?;
        if ctx.has_progress_reporter() {
            if self
                .upstream_binding
                .is_some_and(|binding| binding.era() == ProtocolEra::Modern2026)
            {
                return Err(McpError::invalid_request(
                    "Proxy cannot project a final tools/call result to the legacy handler surface",
                ));
            }
            let content = self.with_backend(|backend| {
                let mut callback = |progress, total, message: Option<String>| {
                    if let Some(total) = total {
                        ctx.report_progress_with_total(progress, total, message.as_deref());
                    } else {
                        ctx.report_progress(progress, message.as_deref());
                    }
                };
                backend.call_tool_with_progress(name, arguments, &mut callback)
            })?;
            return legacy_contents_to_handler(handler_contents_to_legacy(content)?);
        }

        match self.call_tool_typed(ctx, name, arguments)? {
            CoreResult::Legacy(LegacyCoreResult::ToolsCall(result)) => {
                legacy_tool_result_to_handler(result)
            }
            CoreResult::Final(FinalCoreResult::ToolsCall { .. }) => Err(McpError::invalid_request(
                "Proxy cannot project a final tools/call result to the legacy handler surface",
            )),
            _ => Err(unexpected_proxy_result("tools/call")),
        }
    }

    pub fn read_resource(&self, ctx: &McpContext, uri: &str) -> McpResult<Vec<ResourceContent>> {
        match self.read_resource_typed(ctx, uri)? {
            CoreResult::Legacy(LegacyCoreResult::ResourcesRead(result)) => {
                legacy_resource_result_to_handler(result)
            }
            CoreResult::Final(FinalCoreResult::ResourcesRead { .. }) => {
                Err(McpError::invalid_request(
                    "Proxy cannot project a final resources/read result to the legacy handler surface",
                ))
            }
            _ => Err(unexpected_proxy_result("resources/read")),
        }
    }

    pub fn get_prompt(
        &self,
        ctx: &McpContext,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        match self.get_prompt_typed(ctx, name, arguments)? {
            CoreResult::Legacy(LegacyCoreResult::PromptsGet(result)) => {
                legacy_prompt_result_to_handler(result)
            }
            CoreResult::Final(FinalCoreResult::PromptsGet { .. }) => {
                Err(McpError::invalid_request(
                    "Proxy cannot project a final prompts/get result to the legacy handler surface",
                ))
            }
            _ => Err(unexpected_proxy_result("prompts/get")),
        }
    }

    /// Calls a tool without erasing exact legacy fields or final result state.
    pub fn call_tool_typed(
        &self,
        ctx: &McpContext,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<CoreResult> {
        let mut ignore_final_progress = |_| {};
        self.call_tool_typed_with_final_progress(ctx, name, arguments, &mut ignore_final_progress)
    }

    /// Calls a tool without erasing exact result state or final progress
    /// notifications.
    ///
    /// The final callback receives [`FinalProgressNotificationParams`] rather
    /// than IEEE-754 values, preserving the exact JSON-number lexemes admitted
    /// from a modern upstream SSE frame. Exact-2024 backends remain on the
    /// separate [`ProgressCallback`] path and do not invoke this callback.
    pub fn call_tool_typed_with_final_progress(
        &self,
        ctx: &McpContext,
        name: &str,
        arguments: serde_json::Value,
        on_progress: FinalProgressCallback<'_>,
    ) -> McpResult<CoreResult> {
        ctx.checkpoint()?;
        let result = self.with_backend(|backend| {
            backend.call_tool_result_with_final_progress(name, arguments, on_progress)
        })?;
        self.admit_upstream_result("tools/call", result)
    }

    /// Reads a resource without erasing exact legacy fields or final result state.
    pub fn read_resource_typed(&self, ctx: &McpContext, uri: &str) -> McpResult<CoreResult> {
        ctx.checkpoint()?;
        let result = self.with_backend(|backend| backend.read_resource_result(uri))?;
        self.admit_upstream_result("resources/read", result)
    }

    /// Gets a prompt without erasing exact legacy fields or final result state.
    pub fn get_prompt_typed(
        &self,
        ctx: &McpContext,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<CoreResult> {
        ctx.checkpoint()?;
        let result = self.with_backend(|backend| backend.get_prompt_result(name, arguments))?;
        self.admit_upstream_result("prompts/get", result)
    }

    fn call_tool_final(
        &self,
        ctx: &McpContext,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<CompleteResult<FinalCallToolResult>> {
        match self.call_tool_typed(ctx, name, arguments)? {
            CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) => Ok(result),
            CoreResult::Legacy(LegacyCoreResult::ToolsCall(_)) => Err(McpError::invalid_request(
                "Proxy cannot use an exact legacy tools/call result for a final handler path",
            )),
            _ => Err(unexpected_proxy_result("tools/call")),
        }
    }

    pub(crate) fn read_resource_final(
        &self,
        ctx: &McpContext,
        uri: &str,
    ) -> McpResult<CompleteResult<FinalReadResourceResult>> {
        match self.read_resource_typed(ctx, uri)? {
            CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. }) => Ok(result),
            CoreResult::Legacy(LegacyCoreResult::ResourcesRead(_)) => {
                Err(McpError::invalid_request(
                    "Proxy cannot use an exact legacy resources/read result for a final handler path",
                ))
            }
            _ => Err(unexpected_proxy_result("resources/read")),
        }
    }

    pub(crate) fn get_prompt_final(
        &self,
        ctx: &McpContext,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<CompleteResult<FinalGetPromptResult>> {
        match self.get_prompt_typed(ctx, name, arguments)? {
            CoreResult::Final(FinalCoreResult::PromptsGet { result, .. }) => Ok(result),
            CoreResult::Legacy(LegacyCoreResult::PromptsGet(_)) => Err(McpError::invalid_request(
                "Proxy cannot use an exact legacy prompts/get result for a final handler path",
            )),
            _ => Err(unexpected_proxy_result("prompts/get")),
        }
    }

    fn admit_upstream_result(&self, method: &str, result: CoreResult) -> McpResult<CoreResult> {
        if result.method() != method {
            return Err(unexpected_proxy_result(method));
        }
        if let Some(binding) = self.upstream_binding
            && binding.era() != result.era()
        {
            return Err(McpError::invalid_request(
                "Proxy upstream result era contradicts the immutable route binding",
            ));
        }
        Ok(result)
    }
}

pub(crate) struct ProxyToolHandler {
    /// Legacy fallback definition exposed to legacy clients.
    ///
    /// For a final catalog this is only the framework-required legacy handler
    /// shape. [`Self::final_tool`] remains the authoritative catalog entry.
    tool: Tool,
    /// Exact final definition exposed to modern clients, when this handler was
    /// constructed from a final upstream catalog.
    final_tool: Option<fastmcp_protocol::FinalTool>,
    /// The original tool name on the remote server (for forwarding).
    external_name: String,
    client: ProxyClient,
}

impl ProxyToolHandler {
    pub(crate) fn new(tool: Tool, client: ProxyClient) -> Self {
        let external_name = tool.name.clone();
        Self {
            tool,
            final_tool: None,
            external_name,
            client,
        }
    }

    /// Creates a proxy handler with a prefixed name.
    ///
    /// The tool will be exposed with `prefix/original_name` but calls will be
    /// forwarded using the original name.
    pub(crate) fn with_prefix(mut tool: Tool, prefix: &str, client: ProxyClient) -> Self {
        let external_name = tool.name.clone();
        tool.name = format!("{}/{}", prefix, tool.name);
        Self {
            tool,
            final_tool: None,
            external_name,
            client,
        }
    }

    /// Creates a handler from an exact final catalog entry.
    ///
    /// The legacy definition is present only because [`ToolHandler`] has a
    /// legacy base method. Modern catalog registration obtains the unmodified
    /// final definition from [`ToolHandler::final_definition`].
    pub(crate) fn from_final(
        tool: fastmcp_protocol::FinalTool,
        client: ProxyClient,
    ) -> McpResult<Self> {
        if let Some(binding) = client.upstream_binding
            && binding.era() != ProtocolEra::Modern2026
        {
            return Err(McpError::invalid_request(
                "Proxy final tool catalog contradicts the immutable route binding",
            ));
        }
        let external_name = tool.name.clone();
        Ok(Self {
            tool: final_tool_legacy_fallback(&tool),
            final_tool: Some(tool),
            external_name,
            client,
        })
    }

    /// Creates a prefixed handler from an exact final catalog entry.
    pub(crate) fn with_prefix_final(
        mut tool: fastmcp_protocol::FinalTool,
        prefix: &str,
        client: ProxyClient,
    ) -> McpResult<Self> {
        let external_name = tool.name.clone();
        tool.name = format!("{prefix}/{}", tool.name);
        let mut handler = Self::from_final(tool, client)?;
        handler.external_name = external_name;
        Ok(handler)
    }
}

impl ToolHandler for ProxyToolHandler {
    fn definition(&self) -> Tool {
        self.tool.clone()
    }

    fn final_definition(&self) -> Option<fastmcp_protocol::FinalTool> {
        self.final_tool.clone()
    }

    fn final_tool_schema_authority(&self) -> FinalToolSchemaAuthority {
        if self.final_tool.is_some() {
            FinalToolSchemaAuthority::Upstream
        } else {
            FinalToolSchemaAuthority::Local
        }
    }

    fn upstream_final_tool_schema_registration(
        &self,
    ) -> Option<UpstreamFinalToolSchemaRegistration> {
        self.final_tool
            .as_ref()
            .map(|_tool| UpstreamFinalToolSchemaRegistration::exact_proxy())
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        // Forward using the original external name
        self.client.call_tool(ctx, &self.external_name, arguments)
    }

    fn call_final(
        &self,
        ctx: &McpContext,
        arguments: serde_json::Value,
    ) -> McpResult<CompleteResult<FinalCallToolResult>> {
        self.client
            .call_tool_final(ctx, &self.external_name, arguments)
    }

    fn final_tool_error_structured_content(
        &self,
        _kind: crate::handler::ToolErrorKind,
    ) -> Option<serde_json::Value> {
        if self.final_tool.is_some() {
            // Exact-final proxy handlers declare upstream schema authority.
            // They must never synthesize a local `{}` merely to satisfy an
            // upstream scalar outputSchema.
            return None;
        }

        // Legacy proxy handlers use the ordinary local schema path.
        // A proxy cannot consult the upstream for framework-authored error
        // shapes. The empty object is offered for both closed kinds and
        // registration still validates it against the tool's declared
        // outputSchema, so schemas that cannot accept it keep rejecting
        // fail-closed.
        Some(serde_json::json!({}))
    }
}

pub(crate) struct ProxyResourceHandler {
    /// The resource definition as exposed to clients (may have prefixed URI).
    resource: Resource,
    /// The original URI on the remote server (for forwarding).
    external_uri: String,
    /// Exact exposed prefix, including its trailing separator, when one was
    /// deliberately configured. URI schemes must never be inferred as proxy
    /// prefixes.
    uri_prefix: Option<String>,
    template: Option<ResourceTemplate>,
    client: ProxyClient,
}

impl ProxyResourceHandler {
    pub(crate) fn new(resource: Resource, client: ProxyClient) -> Self {
        let external_uri = resource.uri.clone();
        Self {
            resource,
            external_uri,
            uri_prefix: None,
            template: None,
            client,
        }
    }

    /// Creates a proxy handler with a prefixed URI.
    pub(crate) fn with_prefix(mut resource: Resource, prefix: &str, client: ProxyClient) -> Self {
        let external_uri = resource.uri.clone();
        resource.uri = format!("{}/{}", prefix, resource.uri);
        Self {
            resource,
            external_uri,
            uri_prefix: Some(format!("{prefix}/")),
            template: None,
            client,
        }
    }

    pub(crate) fn from_template(template: ResourceTemplate, client: ProxyClient) -> Self {
        let external_uri = template.uri_template.clone();
        Self {
            resource: resource_from_template(&template),
            external_uri,
            uri_prefix: None,
            template: Some(template),
            client,
        }
    }

    /// Creates a proxy handler from a template with a prefixed URI.
    pub(crate) fn from_template_with_prefix(
        mut template: ResourceTemplate,
        prefix: &str,
        client: ProxyClient,
    ) -> Self {
        let external_uri = template.uri_template.clone();
        template.uri_template = format!("{}/{}", prefix, template.uri_template);
        Self {
            resource: resource_from_template(&template),
            external_uri,
            uri_prefix: Some(format!("{prefix}/")),
            template: Some(template),
            client,
        }
    }
}

impl ResourceHandler for ProxyResourceHandler {
    fn definition(&self) -> Resource {
        self.resource.clone()
    }

    fn template(&self) -> Option<ResourceTemplate> {
        self.template.clone()
    }

    fn final_resource_read_cache_hint_provenance(&self) -> FinalResourceReadCacheHintProvenance {
        FinalResourceReadCacheHintProvenance::Explicit
    }

    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        // Forward using the original external URI
        self.client.read_resource(ctx, &self.external_uri)
    }

    fn read_with_uri(
        &self,
        ctx: &McpContext,
        uri: &str,
        _params: &UriParams,
    ) -> McpResult<Vec<ResourceContent>> {
        // Strip only a prefix that this handler explicitly installed. Deriving
        // it from the exposed URI would misclassify `db://` and other schemes,
        // and splitting once would corrupt configured prefixes containing `/`.
        let external_uri = self
            .uri_prefix
            .as_deref()
            .and_then(|prefix| uri.strip_prefix(prefix))
            .unwrap_or(uri);
        self.client.read_resource(ctx, external_uri)
    }

    fn read_final(&self, ctx: &McpContext) -> McpResult<CompleteResult<FinalReadResourceResult>> {
        self.client.read_resource_final(ctx, &self.external_uri)
    }

    fn read_final_with_uri(
        &self,
        ctx: &McpContext,
        uri: &str,
        _params: &UriParams,
    ) -> McpResult<CompleteResult<FinalReadResourceResult>> {
        let external_uri = self
            .uri_prefix
            .as_deref()
            .and_then(|prefix| uri.strip_prefix(prefix))
            .unwrap_or(uri);
        self.client.read_resource_final(ctx, external_uri)
    }
}

pub(crate) struct ProxyPromptHandler {
    /// The prompt definition as exposed to clients (may have prefixed name).
    prompt: Prompt,
    /// The original prompt name on the remote server (for forwarding).
    external_name: String,
    client: ProxyClient,
}

impl ProxyPromptHandler {
    pub(crate) fn new(prompt: Prompt, client: ProxyClient) -> Self {
        let external_name = prompt.name.clone();
        Self {
            prompt,
            external_name,
            client,
        }
    }

    /// Creates a proxy handler with a prefixed name.
    pub(crate) fn with_prefix(mut prompt: Prompt, prefix: &str, client: ProxyClient) -> Self {
        let external_name = prompt.name.clone();
        prompt.name = format!("{}/{}", prefix, prompt.name);
        Self {
            prompt,
            external_name,
            client,
        }
    }
}

impl PromptHandler for ProxyPromptHandler {
    fn definition(&self) -> Prompt {
        self.prompt.clone()
    }

    fn get(
        &self,
        ctx: &McpContext,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        // Forward using the original external name
        self.client.get_prompt(ctx, &self.external_name, arguments)
    }

    fn get_final(
        &self,
        ctx: &McpContext,
        arguments: HashMap<String, String>,
    ) -> McpResult<CompleteResult<FinalGetPromptResult>> {
        self.client
            .get_prompt_final(ctx, &self.external_name, arguments)
    }
}

fn resource_from_template(template: &ResourceTemplate) -> Resource {
    Resource {
        uri: template.uri_template.clone(),
        name: template.name.clone(),
        description: template.description.clone(),
        mime_type: template.mime_type.clone(),
        icon: template.icon.clone(),
        version: template.version.clone(),
        tags: template.tags.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use asupersync::Cx;
    #[cfg(unix)]
    use fastmcp_client::RequestTimeoutPolicy;
    use fastmcp_client::{CanonicalHttpUrl, ClientHttpConnection, ClientProtocolPlan};
    use fastmcp_core::{McpContext, McpErrorCode, block_on};
    use fastmcp_protocol::common_types::ContentBlock;
    use fastmcp_protocol::protocol_policy::{
        HttpModernProbe, HttpProbeBody, ProtocolEra, ProtocolPolicy,
    };
    use fastmcp_protocol::{
        CacheScope, CacheTtl, CallToolResult, ClientCapabilities, ClientInfo, CompleteResult,
        Content, CoreResult, FinalCallToolResult, FinalCoreResult, FinalProgressNotificationParams,
        JsonRpcMessage, LegacyContent, LegacyCoreResult, LegacyPromptMessage,
        LegacyResourceContent, Prompt, PromptMessage, Resource, ResourceContent,
        ServerNotification, Tool, decode_strict_jsonrpc_message,
    };

    use super::{
        MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES, ProxyBackend, ProxyCatalog, ProxyCatalogCacheHint,
        ProxyClient, ProxyFinalCatalog, ProxyHttpClient, ProxyPromptCatalog, ProxyPromptHandler,
        ProxyResourceCatalog, ProxyResourceTemplateCatalog, ProxyToolCatalog, ProxyToolHandler,
        ProxyUpstreamAdapter, ProxyUpstreamBinding, ProxyUpstreamBindingRegistry,
        admit_legacy_interleaved_control_frame, decode_modern_server_notification,
        final_tool_legacy_fallback, forward_modern_progress_notification,
        legacy_contents_to_handler, legacy_prompt_messages_to_handler, legacy_resource_to_handler,
    };
    use crate::handler::{FinalToolSchemaAuthority, PromptHandler, ToolHandler};

    #[test]
    fn proxy_modern_sse_progress_callback_preserves_raw_progress_lexemes() {
        let wire = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"job-17","progress":1.20e+4,"total":12000.0}}"#;
        let JsonRpcMessage::Request(request) = decode_strict_jsonrpc_message(wire.as_bytes(), 4096)
            .expect("exact modern progress notification parses")
        else {
            panic!("fixture is a JSON-RPC notification");
        };

        let mut delivered = Vec::new();
        forward_modern_progress_notification(wire.as_bytes(), &request, &mut |params| {
            delivered.push(params);
        })
        .expect("proxy forwards the exact modern progress notification");
        assert_eq!(delivered.len(), 1);
        let params = &delivered[0];
        assert_eq!(params.progress.as_str(), "1.20e+4");
        assert_eq!(
            params.total.as_ref().map(|total| total.as_str()),
            Some("12000.0")
        );
        let notification = ServerNotification::Progress(params.clone());
        assert_eq!(
            notification
                .encode_wire()
                .expect("notification re-encodes byte-exactly"),
            wire,
            "modern proxy notification handling preserves exact progress lexemes"
        );
    }

    #[test]
    fn proxy_modern_sse_progress_callback_rejects_one_invalid_progress_value() {
        let baseline = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"job-17","progress":1.20e+4,"total":12000.0}}"#;
        let JsonRpcMessage::Request(baseline_request) =
            decode_strict_jsonrpc_message(baseline.as_bytes(), 4096)
                .expect("baseline modern progress notification parses")
        else {
            panic!("baseline is a JSON-RPC notification");
        };
        let baseline_notification =
            decode_modern_server_notification(baseline.as_bytes(), &baseline_request)
                .expect("baseline final progress is admitted");

        let negative = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"job-17","progress":-1,"total":12000.0}}"#;
        let JsonRpcMessage::Request(negative_request) =
            decode_strict_jsonrpc_message(negative.as_bytes(), 4096)
                .expect("one-variable negative progress notification parses")
        else {
            panic!("negative is a JSON-RPC notification");
        };
        let mut delivered = Vec::new();
        let error = forward_modern_progress_notification(
            negative.as_bytes(),
            &negative_request,
            &mut |params| delivered.push(params),
        )
        .expect_err("changing only progress to a negative number must be rejected");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(
            delivered.is_empty(),
            "a rejected modern progress frame must not reach the exact callback"
        );
        assert_eq!(
            baseline_notification
                .encode_wire()
                .expect("baseline notification re-encodes byte-exactly"),
            baseline,
            "the rejected frame cannot alter the admitted raw-parameter baseline"
        );
    }

    #[test]
    fn proxy_projects_closed_exact_legacy_handler_values() {
        let contents = legacy_contents_to_handler(vec![
            LegacyContent::Text {
                text: "ready".to_owned(),
                annotations: None,
                additional: BTreeMap::new(),
            },
            LegacyContent::Resource {
                resource: LegacyResourceContent::Blob {
                    uri: "file:///report.bin".to_owned(),
                    blob: "AAEC".to_owned(),
                    mime_type: Some("application/octet-stream".to_owned()),
                    additional: BTreeMap::new(),
                },
                annotations: None,
                additional: BTreeMap::new(),
            },
        ])
        .expect("closed legacy content is representable by proxy handlers");
        assert_eq!(
            serde_json::to_value(contents).expect("handler content serializes"),
            serde_json::json!([
                {"type": "text", "text": "ready"},
                {
                    "type": "resource",
                    "resource": {
                        "uri": "file:///report.bin",
                        "mimeType": "application/octet-stream",
                        "blob": "AAEC"
                    }
                }
            ])
        );

        let messages = legacy_prompt_messages_to_handler(vec![LegacyPromptMessage {
            role: fastmcp_protocol::Role::Assistant,
            content: LegacyContent::Text {
                text: "summarized".to_owned(),
                annotations: None,
                additional: BTreeMap::new(),
            },
            additional: BTreeMap::new(),
        }])
        .expect("closed legacy prompt messages are representable by proxy handlers");
        assert_eq!(
            serde_json::to_value(messages).expect("handler prompt messages serialize"),
            serde_json::json!([{
                "role": "assistant",
                "content": {"type": "text", "text": "summarized"}
            }])
        );
    }

    #[test]
    fn proxy_rejects_one_legacy_resource_open_member_without_mutating_baseline() {
        let baseline = LegacyResourceContent::Text {
            uri: "file:///open.txt".to_owned(),
            text: "baseline".to_owned(),
            mime_type: Some("text/plain".to_owned()),
            additional: BTreeMap::new(),
        };
        let baseline_wire = serde_json::to_value(
            legacy_resource_to_handler(baseline.clone())
                .expect("the baseline has no unrepresentable open members"),
        )
        .expect("baseline handler resource serializes");
        let planted = LegacyResourceContent::Text {
            uri: "file:///open.txt".to_owned(),
            text: "baseline".to_owned(),
            mime_type: Some("text/plain".to_owned()),
            additional: BTreeMap::from([(
                "com.example/extension".to_owned(),
                serde_json::json!({"retained": true}),
            )]),
        };

        let error = legacy_resource_to_handler(planted)
            .expect_err("adding only one legacy open member must fail closed");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(error.message.contains("open fields"));
        assert_eq!(
            serde_json::to_value(
                legacy_resource_to_handler(baseline)
                    .expect("baseline remains representable after rejection"),
            )
            .expect("baseline handler resource remains serializable"),
            baseline_wire,
            "rejected open state cannot mutate the accepted baseline"
        );
    }

    struct TypedToolBackend {
        result: CoreResult,
        final_progress: Option<FinalProgressNotificationParams>,
    }

    impl ProxyBackend for TypedToolBackend {
        fn list_tools(&mut self) -> fastmcp_core::McpResult<Vec<Tool>> {
            Ok(Vec::new())
        }

        fn list_resources(&mut self) -> fastmcp_core::McpResult<Vec<Resource>> {
            Ok(Vec::new())
        }

        fn list_resource_templates(
            &mut self,
        ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceTemplate>> {
            Ok(Vec::new())
        }

        fn list_prompts(&mut self) -> fastmcp_core::McpResult<Vec<Prompt>> {
            Ok(Vec::new())
        }

        fn call_tool(
            &mut self,
            _name: &str,
            _arguments: serde_json::Value,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Err(fastmcp_core::McpError::internal_error(
                "typed proxy test backend must not use broad content",
            ))
        }

        fn call_tool_with_progress(
            &mut self,
            _name: &str,
            _arguments: serde_json::Value,
            _on_progress: super::ProgressCallback<'_>,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Err(fastmcp_core::McpError::internal_error(
                "typed proxy test backend must not use broad content",
            ))
        }

        fn read_resource(&mut self, _uri: &str) -> fastmcp_core::McpResult<Vec<ResourceContent>> {
            Err(fastmcp_core::McpError::internal_error("not used"))
        }

        fn get_prompt(
            &mut self,
            _name: &str,
            _arguments: HashMap<String, String>,
        ) -> fastmcp_core::McpResult<Vec<PromptMessage>> {
            Err(fastmcp_core::McpError::internal_error("not used"))
        }

        fn call_tool_result(
            &mut self,
            _name: &str,
            _arguments: serde_json::Value,
        ) -> fastmcp_core::McpResult<CoreResult> {
            Ok(self.result.clone())
        }

        fn call_tool_result_with_final_progress(
            &mut self,
            _name: &str,
            _arguments: serde_json::Value,
            on_progress: super::FinalProgressCallback<'_>,
        ) -> fastmcp_core::McpResult<CoreResult> {
            if let Some(params) = &self.final_progress {
                on_progress(params.clone());
            }
            Ok(self.result.clone())
        }
    }

    fn proxy_test_tool() -> Tool {
        Tool {
            name: "exact-result".to_owned(),
            description: None,
            input_schema: serde_json::json!({}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn proxy_binding(era: ProtocolEra) -> ProxyUpstreamBinding {
        ProxyUpstreamBinding {
            era,
            adapter: match era {
                ProtocolEra::Modern2026 => ProxyUpstreamAdapter::ModernStdio,
                ProtocolEra::Legacy2024 => ProxyUpstreamAdapter::LegacyStdio,
            },
            policy: match era {
                ProtocolEra::Modern2026 => ProtocolPolicy::ModernOnly,
                ProtocolEra::Legacy2024 => ProtocolPolicy::LegacyOnly,
            },
            configuration_generation: 41,
        }
    }

    #[test]
    fn proxy_auto_http_refusal_requires_legacy_endpoint_validation_before_binding() {
        let modern = CanonicalHttpUrl::parse("https://api.example.test/mcp")
            .expect("canonical modern target");
        let legacy_sse = CanonicalHttpUrl::parse("https://api.example.test/sse")
            .expect("canonical legacy SSE target");
        let legacy_message = CanonicalHttpUrl::parse("https://api.example.test/messages")
            .expect("canonical legacy POST target");
        let mut bindings = ProxyUpstreamBindingRegistry::default();

        let error = bindings
            .bind_http(
                "upstream-route",
                "native-h1:upstream-route",
                "adapter-receipt",
                1,
                ProtocolPolicy::Auto,
                Some(modern.clone()),
                Some(legacy_sse.clone()),
                Some(legacy_message.clone()),
                "credential-partition".to_owned(),
                "security-partition".to_owned(),
                "http-sse-v2".to_owned(),
                1,
                1,
                HttpModernProbe {
                    status: 404,
                    body: HttpProbeBody::Empty,
                },
            )
            .expect_err("an Auto fallback authorization cannot bind the legacy adapter");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(error.message.contains("before endpoint validation"));

        let binding = bindings
            .bind_http(
                "upstream-route",
                "native-h1:upstream-route",
                "adapter-receipt",
                1,
                ProtocolPolicy::Auto,
                Some(modern),
                Some(legacy_sse),
                Some(legacy_message),
                "credential-partition".to_owned(),
                "security-partition".to_owned(),
                "http-sse-v2".to_owned(),
                1,
                1,
                HttpModernProbe {
                    status: 200,
                    body: HttpProbeBody::RecognizedModernJsonRpc,
                },
            )
            .expect("the unchanged binding can still select a recognized modern response");
        assert_eq!(binding.era(), ProtocolEra::Modern2026);
        assert_eq!(binding.adapter(), ProxyUpstreamAdapter::ModernHttp);
    }

    fn final_tool_result_with_open_members() -> CoreResult {
        CoreResult::Final(FinalCoreResult::ToolsCall {
            result: CompleteResult::new(
                FinalCallToolResult {
                    content: vec![ContentBlock::Text {
                        text: "final payload".to_owned(),
                        annotations: None,
                        meta: None,
                        additional: BTreeMap::from([(
                            "com.example/extension".to_owned(),
                            serde_json::json!({"retained": true}),
                        )]),
                    }],
                    is_error: false,
                    structured_content: Some(serde_json::json!({"answer": 42})),
                },
                crate::handler::empty_final_result_meta().expect("empty final metadata"),
            ),
            diagnostic: None,
        })
    }

    #[test]
    fn typed_modern_proxy_forwards_exact_progress_to_its_final_callback() {
        let wire = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"job-19","progress":1.20e+4,"total":12000.0}}"#;
        let JsonRpcMessage::Request(request) = decode_strict_jsonrpc_message(wire.as_bytes(), 4096)
            .expect("exact final progress fixture parses")
        else {
            panic!("fixture is a JSON-RPC notification");
        };
        let ServerNotification::Progress(progress) =
            decode_modern_server_notification(wire.as_bytes(), &request)
                .expect("exact final progress fixture is admitted")
        else {
            panic!("fixture decodes as final progress");
        };
        let proxy = ProxyClient::from_backend_with_upstream_binding(
            TypedToolBackend {
                result: final_tool_result_with_open_members(),
                final_progress: Some(progress),
            },
            proxy_binding(ProtocolEra::Modern2026),
            "2026-07-28",
        )
        .expect("matching final upstream binding");
        let context = McpContext::new(Cx::for_testing(), 500);
        let mut delivered = Vec::new();

        let result = proxy
            .call_tool_typed_with_final_progress(
                &context,
                "exact-result",
                serde_json::json!({}),
                &mut |params| delivered.push(params),
            )
            .expect("typed modern proxy accepts progress rather than using a legacy projection");

        assert!(matches!(
            result,
            CoreResult::Final(FinalCoreResult::ToolsCall { .. })
        ));
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].progress.as_str(), "1.20e+4");
        assert_eq!(
            delivered[0].total.as_ref().map(|total| total.as_str()),
            Some("12000.0")
        );
    }

    #[test]
    fn proxy_final_handler_preserves_modern_result_and_rejects_one_era_contradiction() {
        let upstream_result = final_tool_result_with_open_members();
        let modern_proxy = ProxyClient::from_backend_with_upstream_binding(
            TypedToolBackend {
                result: upstream_result.clone(),
                final_progress: None,
            },
            proxy_binding(ProtocolEra::Modern2026),
            "2026-07-28",
        )
        .expect("matching final upstream binding");
        let modern_handler = ProxyToolHandler::from_final(final_catalog_tool(), modern_proxy)
            .expect("an exact final catalog entry creates a forwarding handler");
        let context = McpContext::new(Cx::for_testing(), 501);

        assert_eq!(
            modern_handler.final_tool_schema_authority(),
            FinalToolSchemaAuthority::Upstream
        );

        let final_result = modern_handler
            .call_final(&context, serde_json::json!({}))
            .expect("the final hook retains the upstream final result");
        assert_eq!(
            final_result.payload.structured_content,
            Some(serde_json::json!({"answer": 42}))
        );
        let [ContentBlock::Text { additional, .. }] = final_result.payload.content.as_slice()
        else {
            panic!("expected preserved final text content");
        };
        assert_eq!(additional["com.example/extension"]["retained"], true);

        let contradictory_proxy = ProxyClient::from_backend_with_upstream_binding(
            TypedToolBackend {
                result: upstream_result,
                final_progress: None,
            },
            proxy_binding(ProtocolEra::Legacy2024),
            fastmcp_protocol::PROTOCOL_VERSION,
        )
        .expect("only the selected binding era differs");
        let contradictory_handler = ProxyToolHandler::new(proxy_test_tool(), contradictory_proxy);
        let error = contradictory_handler
            .call_final(&context, serde_json::json!({}))
            .expect_err("a final upstream result cannot cross a legacy binding");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(error.message.contains("contradicts"));
    }

    #[test]
    fn proxy_exposes_legacy_open_members_without_projecting_them_to_content() {
        let upstream_result = CoreResult::Legacy(LegacyCoreResult::ToolsCall(CallToolResult {
            content: vec![LegacyContent::Text {
                text: "legacy payload".to_owned(),
                annotations: None,
                additional: BTreeMap::from([(
                    "com.example/content".to_owned(),
                    serde_json::json!({"retained": true}),
                )]),
            }],
            is_error: false,
            meta: None,
            additional: BTreeMap::from([(
                "com.example/result".to_owned(),
                serde_json::json!({"retained": true}),
            )]),
        }));
        let proxy = ProxyClient::from_backend_with_upstream_binding(
            TypedToolBackend {
                result: upstream_result,
                final_progress: None,
            },
            proxy_binding(ProtocolEra::Legacy2024),
            fastmcp_protocol::PROTOCOL_VERSION,
        )
        .expect("matching exact legacy binding");
        let context = McpContext::new(Cx::for_testing(), 502);

        let CoreResult::Legacy(LegacyCoreResult::ToolsCall(result)) = proxy
            .call_tool_typed(&context, "exact-result", serde_json::json!({}))
            .expect("the typed proxy surface retains the exact legacy result")
        else {
            panic!("expected exact legacy tools/call result");
        };
        assert_eq!(result.additional["com.example/result"]["retained"], true);
        let [LegacyContent::Text { additional, .. }] = result.content.as_slice() else {
            panic!("expected exact legacy text content");
        };
        assert_eq!(additional["com.example/content"]["retained"], true);

        let error = proxy
            .call_tool(&context, "exact-result", serde_json::json!({}))
            .expect_err("the broad legacy handler surface cannot erase exact open members");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(error.message.contains("open fields"));
    }

    #[derive(Default)]
    struct TestState {
        last_tool: Option<(String, serde_json::Value)>,
        last_resource: Option<String>,
        last_prompt: Option<(String, HashMap<String, String>)>,
    }

    #[derive(Clone, Default)]
    struct TestBackend {
        tools: Vec<Tool>,
        resources: Vec<Resource>,
        prompts: Vec<Prompt>,
        state: Arc<Mutex<TestState>>,
    }

    impl ProxyBackend for TestBackend {
        fn list_tools(&mut self) -> fastmcp_core::McpResult<Vec<Tool>> {
            Ok(self.tools.clone())
        }

        fn list_resources(&mut self) -> fastmcp_core::McpResult<Vec<Resource>> {
            Ok(self.resources.clone())
        }

        fn list_resource_templates(
            &mut self,
        ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceTemplate>> {
            Ok(Vec::new())
        }

        fn list_prompts(&mut self) -> fastmcp_core::McpResult<Vec<Prompt>> {
            Ok(self.prompts.clone())
        }

        fn call_tool(
            &mut self,
            name: &str,
            arguments: serde_json::Value,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            let mut guard = self.state.lock().expect("state lock poisoned");
            guard.last_tool.replace((name.to_string(), arguments));
            Ok(vec![Content::Text {
                text: "ok".to_string(),
            }])
        }

        fn call_tool_with_progress(
            &mut self,
            name: &str,
            arguments: serde_json::Value,
            on_progress: super::ProgressCallback<'_>,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            on_progress(0.5, Some(1.0), Some("half".to_string()));
            self.call_tool(name, arguments)
        }

        fn read_resource(&mut self, uri: &str) -> fastmcp_core::McpResult<Vec<ResourceContent>> {
            self.state
                .lock()
                .expect("state lock poisoned")
                .last_resource
                .replace(uri.to_string());
            Ok(vec![ResourceContent {
                uri: "test://resource".to_string(),
                text: Some("resource".to_string()),
                mime_type: None,
                blob: None,
            }])
        }

        fn get_prompt(
            &mut self,
            name: &str,
            arguments: HashMap<String, String>,
        ) -> fastmcp_core::McpResult<Vec<PromptMessage>> {
            let mut guard = self.state.lock().expect("state lock poisoned");
            guard.last_prompt.replace((name.to_string(), arguments));
            Ok(vec![PromptMessage {
                role: fastmcp_protocol::Role::Assistant,
                content: Content::Text {
                    text: "ok".to_string(),
                },
            }])
        }
    }

    struct FinalCatalogBackend {
        tool: fastmcp_protocol::FinalTool,
        reject_exact_catalog: bool,
    }

    impl ProxyBackend for FinalCatalogBackend {
        fn list_tools(&mut self) -> fastmcp_core::McpResult<Vec<Tool>> {
            Err(fastmcp_core::McpError::internal_error(
                "final catalog must not be projected to legacy tools",
            ))
        }

        fn list_tool_catalog(&mut self) -> fastmcp_core::McpResult<ProxyToolCatalog> {
            if self.reject_exact_catalog {
                return Err(fastmcp_core::McpError::invalid_request(
                    "final catalog is unavailable",
                ));
            }
            Ok(ProxyToolCatalog::Final(ProxyFinalCatalog::new(vec![
                self.tool.clone(),
            ])))
        }

        fn list_resources(&mut self) -> fastmcp_core::McpResult<Vec<Resource>> {
            Ok(Vec::new())
        }

        fn list_resource_templates(
            &mut self,
        ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceTemplate>> {
            Ok(Vec::new())
        }

        fn list_prompts(&mut self) -> fastmcp_core::McpResult<Vec<Prompt>> {
            Ok(Vec::new())
        }

        fn call_tool(
            &mut self,
            _name: &str,
            _arguments: serde_json::Value,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Err(fastmcp_core::McpError::internal_error("not used"))
        }

        fn call_tool_with_progress(
            &mut self,
            _name: &str,
            _arguments: serde_json::Value,
            _on_progress: super::ProgressCallback<'_>,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Err(fastmcp_core::McpError::internal_error("not used"))
        }

        fn read_resource(&mut self, _uri: &str) -> fastmcp_core::McpResult<Vec<ResourceContent>> {
            Err(fastmcp_core::McpError::internal_error("not used"))
        }

        fn get_prompt(
            &mut self,
            _name: &str,
            _arguments: HashMap<String, String>,
        ) -> fastmcp_core::McpResult<Vec<PromptMessage>> {
            Err(fastmcp_core::McpError::internal_error("not used"))
        }
    }

    struct FinalTypedCatalogBackend {
        tool: fastmcp_protocol::FinalTool,
        resource: fastmcp_protocol::FinalResource,
        template: fastmcp_protocol::FinalResourceTemplate,
        prompt: fastmcp_protocol::FinalPrompt,
    }

    impl ProxyBackend for FinalTypedCatalogBackend {
        fn list_tools(&mut self) -> fastmcp_core::McpResult<Vec<Tool>> {
            Err(fastmcp_core::McpError::internal_error(
                "final catalog must not be projected to legacy tools",
            ))
        }

        fn list_tool_catalog(&mut self) -> fastmcp_core::McpResult<ProxyToolCatalog> {
            let ttl_ms = serde_json::from_str("922337203685477580812345678901234567890")
                .expect("arbitrary-width final TTL is valid");
            Ok(ProxyToolCatalog::Final(ProxyFinalCatalog::single_page(
                vec![self.tool.clone()],
                ttl_ms,
                CacheScope::Public,
            )))
        }

        fn list_resources(&mut self) -> fastmcp_core::McpResult<Vec<Resource>> {
            Err(fastmcp_core::McpError::internal_error(
                "final catalog must not be projected to legacy resources",
            ))
        }

        fn list_resource_catalog(&mut self) -> fastmcp_core::McpResult<ProxyResourceCatalog> {
            Ok(ProxyResourceCatalog::Final(ProxyFinalCatalog::single_page(
                vec![self.resource.clone()],
                CacheTtl::milliseconds(0),
                CacheScope::Private,
            )))
        }

        fn list_resource_templates(
            &mut self,
        ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceTemplate>> {
            Err(fastmcp_core::McpError::internal_error(
                "final catalog must not be projected to legacy resource templates",
            ))
        }

        fn list_resource_template_catalog(
            &mut self,
        ) -> fastmcp_core::McpResult<ProxyResourceTemplateCatalog> {
            Ok(ProxyResourceTemplateCatalog::Final(
                ProxyFinalCatalog::single_page(
                    vec![self.template.clone()],
                    CacheTtl::milliseconds(0),
                    CacheScope::Private,
                ),
            ))
        }

        fn list_prompts(&mut self) -> fastmcp_core::McpResult<Vec<Prompt>> {
            Err(fastmcp_core::McpError::internal_error(
                "final catalog must not be projected to legacy prompts",
            ))
        }

        fn list_prompt_catalog(&mut self) -> fastmcp_core::McpResult<ProxyPromptCatalog> {
            Ok(ProxyPromptCatalog::Final(ProxyFinalCatalog::single_page(
                vec![self.prompt.clone()],
                CacheTtl::milliseconds(0),
                CacheScope::Private,
            )))
        }

        fn call_tool(
            &mut self,
            _name: &str,
            _arguments: serde_json::Value,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Err(fastmcp_core::McpError::internal_error("not used"))
        }

        fn call_tool_with_progress(
            &mut self,
            _name: &str,
            _arguments: serde_json::Value,
            _on_progress: super::ProgressCallback<'_>,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Err(fastmcp_core::McpError::internal_error("not used"))
        }

        fn read_resource(&mut self, _uri: &str) -> fastmcp_core::McpResult<Vec<ResourceContent>> {
            Err(fastmcp_core::McpError::internal_error("not used"))
        }

        fn get_prompt(
            &mut self,
            _name: &str,
            _arguments: HashMap<String, String>,
        ) -> fastmcp_core::McpResult<Vec<PromptMessage>> {
            Err(fastmcp_core::McpError::internal_error("not used"))
        }
    }

    fn final_catalog_tool() -> fastmcp_protocol::FinalTool {
        serde_json::from_value(serde_json::json!({
            "name": "weather",
            "title": "Weather Forecast",
            "description": "Returns a precise forecast.",
            "icons": [{
                "src": "https://example.test/icons/weather.svg",
                "mimeType": "image/svg+xml",
                "sizes": ["16x16", "32x32"],
                "theme": "light",
                "com.example/icon": {"retained": true}
            }],
            "inputSchema": {
                "type": "object",
                "properties": {"city": {"type": "string"}}
            },
            "outputSchema": {"type": "object"},
            "annotations": {
                "title": "Forecast",
                "destructiveHint": false,
                "idempotentHint": true,
                "readOnlyHint": true,
                "openWorldHint": false
            },
            "_meta": {"com.example/catalog": {"retained": true}}
        }))
        .expect("the final tool fixture is exact-schema valid")
    }

    fn final_catalog_resource() -> fastmcp_protocol::FinalResource {
        serde_json::from_str(
            r#"{
                "uri": "https://example.test/forecast/today",
                "name": "today-forecast",
                "title": "Today's Forecast",
                "description": "The current forecast.",
                "icons": [{
                    "src": "https://example.test/icons/forecast.svg",
                    "mimeType": "image/svg+xml",
                    "sizes": ["16x16", "32x32"],
                    "theme": "dark",
                    "com.example/icon": {"retained": true}
                }],
                "mimeType": "application/json",
                "size": 922337203685477580812345678901234567890,
                "annotations": {"audience": ["assistant"], "priority": 0.75},
                "_meta": {"com.example/resource": {"retained": true}}
            }"#,
        )
        .expect("the final resource fixture is exact-schema valid")
    }

    fn final_catalog_resource_template() -> fastmcp_protocol::FinalResourceTemplate {
        serde_json::from_value(serde_json::json!({
            "uriTemplate": "https://example.test/forecast/{city}",
            "name": "city-forecast",
            "title": "City Forecast",
            "description": "A forecast for one city.",
            "icons": [{"src": "https://example.test/icons/city.svg"}],
            "mimeType": "application/json",
            "annotations": {"audience": ["user"]},
            "_meta": {"com.example/template": {"retained": true}}
        }))
        .expect("the final resource template fixture is exact-schema valid")
    }

    fn final_catalog_prompt() -> fastmcp_protocol::FinalPrompt {
        serde_json::from_value(serde_json::json!({
            "name": "forecast-summary",
            "title": "Forecast Summary",
            "description": "Summarize one forecast.",
            "icons": [{"src": "https://example.test/icons/prompt.svg"}],
            "arguments": [{
                "name": "city",
                "title": "City Name",
                "description": "The city to summarize.",
                "required": true
            }],
            "_meta": {"com.example/prompt": {"retained": true}}
        }))
        .expect("the final prompt fixture is exact-schema valid")
    }

    #[test]
    fn proxy_catalog_preserves_final_tool_bytes_without_legacy_projection() {
        let tool = final_catalog_tool();
        let expected_wire = serde_json::to_vec(&tool).expect("final tool serializes");
        let mut backend = FinalCatalogBackend {
            tool,
            reject_exact_catalog: false,
        };

        let catalog = ProxyCatalog::from_backend(&mut backend)
            .expect("exact final tool catalog is accepted without a legacy projection");

        assert!(catalog.tools.is_empty());
        assert_eq!(catalog.final_tools.len(), 1);
        assert_eq!(
            serde_json::to_vec(&catalog.final_tools[0]).expect("catalog final tool serializes"),
            expected_wire,
            "final-only tool members must remain byte-for-byte serializable"
        );
    }

    #[test]
    fn typed_catalog_autodiscovers_final_metadata_without_prebinding() {
        let tool = final_catalog_tool();
        let resource = final_catalog_resource();
        let template = final_catalog_resource_template();
        let prompt = final_catalog_prompt();
        let expected_tool = serde_json::to_vec(&tool).expect("final tool serializes");
        let expected_resource = serde_json::to_vec(&resource).expect("final resource serializes");
        let expected_template =
            serde_json::to_vec(&template).expect("final resource template serializes");
        let expected_prompt = serde_json::to_vec(&prompt).expect("final prompt serializes");

        let catalog = ProxyClient::from_backend(FinalTypedCatalogBackend {
            tool,
            resource,
            template,
            prompt,
        })
        .catalog_typed()
        .expect("automatic final discovery does not require a caller-supplied era");

        assert_eq!(
            catalog.era().expect("catalog has one era"),
            ProtocolEra::Modern2026
        );
        let tools = catalog
            .final_tools()
            .expect("automatic discovery must retain the final tool model");
        let resources = catalog
            .final_resources()
            .expect("automatic discovery must retain the final resource model");
        let templates = catalog
            .final_resource_templates()
            .expect("automatic discovery must retain the final resource-template model");
        let prompts = catalog
            .final_prompts()
            .expect("automatic discovery must retain the final prompt model");
        assert_eq!(
            serde_json::to_vec(&tools[0]).expect("tool serializes"),
            expected_tool
        );
        assert_eq!(
            serde_json::to_vec(&resources[0]).expect("resource serializes"),
            expected_resource
        );
        assert_eq!(
            resources[0].size.as_ref().map(|size| size.as_str()),
            Some("922337203685477580812345678901234567890"),
            "the proxy catalog retains the exact arbitrary-width final resource size"
        );
        assert_eq!(
            serde_json::to_vec(&templates[0]).expect("template serializes"),
            expected_template
        );
        assert_eq!(
            serde_json::to_vec(&prompts[0]).expect("prompt serializes"),
            expected_prompt
        );
    }

    #[test]
    fn proxy_catalog_retains_every_exact_final_component_without_projection() {
        let tool = final_catalog_tool();
        let resource = final_catalog_resource();
        let template = final_catalog_resource_template();
        let prompt = final_catalog_prompt();
        let expected_tool = serde_json::to_vec(&tool).expect("tool serializes");
        let expected_resource = serde_json::to_vec(&resource).expect("resource serializes");
        let expected_template = serde_json::to_vec(&template).expect("template serializes");
        let expected_prompt = serde_json::to_vec(&prompt).expect("prompt serializes");
        let mut backend = FinalTypedCatalogBackend {
            tool,
            resource,
            template,
            prompt,
        };

        let catalog = ProxyCatalog::from_backend(&mut backend)
            .expect("the complete final catalog is retained without legacy projections");

        assert_eq!(
            catalog.era().expect("catalog has one exact era"),
            ProtocolEra::Modern2026
        );
        assert!(catalog.tools.is_empty());
        assert!(catalog.resources.is_empty());
        assert!(catalog.resource_templates.is_empty());
        assert!(catalog.prompts.is_empty());
        assert_eq!(catalog.final_tool_cache_hints.len(), 1);
        assert_eq!(
            catalog.final_tool_cache_hints[0].ttl_ms.as_str(),
            "922337203685477580812345678901234567890"
        );
        assert_eq!(
            catalog.final_tool_cache_hints[0].cache_scope,
            CacheScope::Public
        );
        assert_eq!(catalog.final_resource_cache_hints[0].ttl_ms.as_str(), "0");
        assert_eq!(
            catalog.final_resource_cache_hints[0].cache_scope,
            CacheScope::Private
        );
        assert_eq!(catalog.final_resource_template_cache_hints.len(), 1);
        assert_eq!(catalog.final_prompt_cache_hints.len(), 1);
        assert_eq!(
            serde_json::to_vec(&catalog.final_tools[0]).expect("tool serializes"),
            expected_tool
        );
        assert_eq!(
            serde_json::to_vec(&catalog.final_resources[0]).expect("resource serializes"),
            expected_resource
        );
        assert_eq!(
            serde_json::to_vec(&catalog.final_resource_templates[0]).expect("template serializes"),
            expected_template
        );
        assert_eq!(
            serde_json::to_vec(&catalog.final_prompts[0]).expect("prompt serializes"),
            expected_prompt
        );
    }

    #[test]
    fn proxy_catalog_rejects_one_legacy_component_added_to_a_final_catalog() {
        let baseline = ProxyCatalog {
            tool_catalog_era: Some(ProtocolEra::Modern2026),
            final_tools: vec![final_catalog_tool()],
            final_resources: vec![final_catalog_resource()],
            final_resource_templates: vec![final_catalog_resource_template()],
            final_prompts: vec![final_catalog_prompt()],
            ..ProxyCatalog::default()
        };
        assert_eq!(
            baseline.era().expect("complete final baseline is admitted"),
            ProtocolEra::Modern2026
        );
        let baseline_wire = serde_json::to_vec(&baseline.final_resources[0])
            .expect("baseline final resource serializes");

        let mut mixed = baseline.clone();
        mixed.resources.push(Resource {
            uri: "mcp://legacy-only/resource".to_owned(),
            name: "legacy-only-resource".to_owned(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: Vec::new(),
        });

        let error = mixed
            .era()
            .expect_err("adding only a legacy resource must reject the mixed-era catalog");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(error.message.contains("legacy tools, resources"));
        assert_eq!(
            serde_json::to_vec(&baseline.final_resources[0])
                .expect("baseline final resource remains serializable"),
            baseline_wire,
            "rejected mixed state cannot mutate the admitted final baseline"
        );
    }

    #[test]
    fn proxy_catalog_rejects_one_non_advancing_modern_cursor_without_replacing_catalog() {
        let retained_catalog = ProxyCatalog {
            tool_catalog_era: Some(ProtocolEra::Modern2026),
            final_tools: vec![final_catalog_tool()],
            ..ProxyCatalog::default()
        };
        let retained_tool_wire = serde_json::to_vec(&retained_catalog.final_tools)
            .expect("retained final tools serialize");

        let mut second_page = final_catalog_tool();
        second_page.name = "weather-page-two".to_owned();
        let first_page = final_catalog_tool();
        let page_hint =
            || ProxyCatalogCacheHint::new(CacheTtl::milliseconds(0), CacheScope::Private);
        let mut page_requests = 0;
        let replacement = super::collect_modern_proxy_catalog_pages(
            fastmcp_protocol::methods::TOOLS_LIST,
            |cursor| {
                page_requests += 1;
                match cursor {
                    None => Ok((
                        vec![first_page.clone()],
                        Some("tools-page-2".to_owned()),
                        page_hint(),
                    )),
                    Some("tools-page-2") => {
                        // The one forbidden difference from the terminal
                        // positive page is retaining this same cursor.
                        Ok((
                            vec![second_page.clone()],
                            Some("tools-page-2".to_owned()),
                            page_hint(),
                        ))
                    }
                    Some(cursor) => Err(fastmcp_core::McpError::invalid_request(format!(
                        "unexpected test cursor {cursor}"
                    ))),
                }
            },
        )
        .map(|final_tools| ProxyCatalog {
            tool_catalog_era: Some(ProtocolEra::Modern2026),
            final_tools: final_tools.entries,
            final_tool_cache_hints: final_tools.cache_hints,
            ..ProxyCatalog::default()
        });
        let error = replacement.expect_err(
            "only changing the terminal nextCursor to the current cursor must fail closed",
        );
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(error.message.contains("non-advancing cursor"));
        assert_eq!(
            page_requests, 2,
            "the repeated cursor is rejected before a third catalog request"
        );

        assert_eq!(
            serde_json::to_vec(&retained_catalog.final_tools)
                .expect("retained final tools remain serializable"),
            retained_tool_wire,
            "the failed replacement cannot expose the first partial modern page"
        );
    }

    #[test]
    fn proxy_catalog_retains_each_final_page_cache_hint_losslessly() {
        let huge_ttl: CacheTtl = serde_json::from_str("922337203685477580812345678901234567890")
            .expect("arbitrary-width final TTL is valid");
        let catalog = super::collect_modern_proxy_catalog_pages(
            fastmcp_protocol::methods::TOOLS_LIST,
            |cursor| match cursor {
                None => Ok((
                    vec![final_catalog_tool()],
                    Some("tools-page-2".to_owned()),
                    ProxyCatalogCacheHint::new(huge_ttl.clone(), CacheScope::Public),
                )),
                Some("tools-page-2") => Ok((
                    vec![final_catalog_tool()],
                    None,
                    ProxyCatalogCacheHint::new(CacheTtl::milliseconds(0), CacheScope::Private),
                )),
                Some(cursor) => Err(fastmcp_core::McpError::invalid_request(format!(
                    "unexpected test cursor {cursor}"
                ))),
            },
        )
        .expect("a two-page final catalog is materialized");

        assert_eq!(catalog.entries.len(), 2);
        assert_eq!(catalog.cache_hints.len(), 2);
        assert_eq!(catalog.cache_hints[0].ttl_ms.as_str(), huge_ttl.as_str());
        assert_eq!(catalog.cache_hints[0].cache_scope, CacheScope::Public);
        assert_eq!(catalog.cache_hints[1].ttl_ms.as_str(), "0");
        assert_eq!(catalog.cache_hints[1].cache_scope, CacheScope::Private);
    }

    #[test]
    fn typed_catalog_rejects_one_field_legacy_binding_contradiction() {
        let proxy = ProxyClient::from_backend_with_upstream_binding(
            FinalTypedCatalogBackend {
                tool: final_catalog_tool(),
                resource: final_catalog_resource(),
                template: final_catalog_resource_template(),
                prompt: final_catalog_prompt(),
            },
            proxy_binding(ProtocolEra::Legacy2024),
            ProtocolEra::Legacy2024.version().as_str(),
        )
        .expect("only the immutable binding era differs from the positive path");

        let error = proxy
            .catalog_typed()
            .expect_err("a final catalog cannot cross a legacy route binding");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(error.message.contains("contradicts"));
    }

    #[test]
    fn proxy_catalog_rejects_a_final_catalog_failure_without_legacy_fallback() {
        let mut backend = FinalCatalogBackend {
            tool: final_catalog_tool(),
            reject_exact_catalog: true,
        };

        let error = ProxyCatalog::from_backend(&mut backend)
            .expect_err("a failed final catalog must not be silently downgraded");

        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(error.message.contains("final catalog is unavailable"));
    }

    #[test]
    fn final_catalog_creates_lossless_proxy_tool_handlers_for_a_modern_binding() {
        let mut expected_tool = final_catalog_tool();
        expected_tool.output_schema = Some(serde_json::json!({
            "type": "string",
            "com.example/schema": {"retained": true}
        }));
        let expected_wire = serde_json::to_vec(&expected_tool).expect("final tool serializes");
        let proxy = ProxyClient::from_backend_with_upstream_binding(
            FinalCatalogBackend {
                tool: expected_tool,
                reject_exact_catalog: false,
            },
            proxy_binding(ProtocolEra::Modern2026),
            ProtocolEra::Modern2026.version().as_str(),
        )
        .expect("the modern route binding accepts the final upstream version");

        let catalog = proxy.catalog().expect("modern catalog matches its binding");
        let handlers = catalog
            .final_tool_handlers(proxy)
            .expect("final catalog entries are consumable by proxy handlers");

        assert!(catalog.tools.is_empty());
        assert_eq!(handlers.len(), 1);
        assert_eq!(
            handlers[0].final_tool_schema_authority(),
            FinalToolSchemaAuthority::Upstream,
            "an exact-final catalog entry must delegate its scalar output schema upstream"
        );
        assert_eq!(
            serde_json::to_vec(
                &handlers[0]
                    .final_definition()
                    .expect("final proxy handler retains its final definition"),
            )
            .expect("handler final definition serializes"),
            expected_wire,
            "the handler must expose the upstream final definition without a legacy projection"
        );
    }

    #[test]
    fn legacy_proxy_tool_handler_keeps_local_schema_authority() {
        let handler = ProxyToolHandler::new(
            final_tool_legacy_fallback(&final_catalog_tool()),
            ProxyClient::from_backend(FinalCatalogBackend {
                tool: final_catalog_tool(),
                reject_exact_catalog: false,
            }),
        );

        assert_eq!(
            handler.final_tool_schema_authority(),
            FinalToolSchemaAuthority::Local,
            "changing only the handler construction to legacy must not bypass local validation"
        );
        assert!(
            handler.final_definition().is_none(),
            "a legacy handler cannot claim to retain exact-final schema or metadata bytes"
        );
    }

    #[test]
    fn final_catalog_rejects_the_same_entry_for_a_legacy_binding() {
        let proxy = ProxyClient::from_backend_with_upstream_binding(
            FinalCatalogBackend {
                tool: final_catalog_tool(),
                reject_exact_catalog: false,
            },
            proxy_binding(ProtocolEra::Legacy2024),
            ProtocolEra::Legacy2024.version().as_str(),
        )
        .expect("the unchanged legacy route binding accepts its legacy upstream version");

        let error = proxy
            .catalog()
            .expect_err("only the route era differs, so the final catalog must be rejected");

        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(error.message.contains("catalog era contradicts"));
    }

    #[test]
    fn cached_binding_invalidation_removes_only_the_exact_generation() {
        let selected = proxy_binding(ProtocolEra::Modern2026);
        let retained = ProxyUpstreamBinding {
            configuration_generation: selected.configuration_generation + 1,
            ..selected
        };
        let mut registry = ProxyUpstreamBindingRegistry::default();
        registry.stdio.insert(
            super::StdioBindingKey {
                route_identity: "weather-route".to_owned(),
                transport_identity: "stdio:weather".to_owned(),
                adapter_receipt_identity: "receipt-b".to_owned(),
                policy: selected.policy,
                configuration_generation: selected.configuration_generation,
            },
            selected,
        );
        registry.stdio.insert(
            super::StdioBindingKey {
                route_identity: "weather-route".to_owned(),
                transport_identity: "stdio:weather".to_owned(),
                adapter_receipt_identity: "receipt-a".to_owned(),
                policy: selected.policy,
                configuration_generation: selected.configuration_generation,
            },
            selected,
        );
        registry.stdio.insert(
            super::StdioBindingKey {
                route_identity: "weather-route".to_owned(),
                transport_identity: "stdio:weather".to_owned(),
                adapter_receipt_identity: "receipt-a".to_owned(),
                policy: retained.policy,
                configuration_generation: retained.configuration_generation,
            },
            retained,
        );

        let removed = registry
            .invalidate_cached_binding("weather-route", "stdio:weather", "receipt-a", selected)
            .expect("the exact configured binding can be invalidated");

        assert_eq!(removed, 1);
        assert_eq!(registry.stdio.len(), 2);
        assert!(registry.stdio.contains_key(&super::StdioBindingKey {
            route_identity: "weather-route".to_owned(),
            transport_identity: "stdio:weather".to_owned(),
            adapter_receipt_identity: "receipt-b".to_owned(),
            policy: selected.policy,
            configuration_generation: selected.configuration_generation,
        }));
        assert!(registry.stdio.values().any(|binding| *binding == retained));
    }

    #[test]
    fn cached_binding_invalidation_keeps_an_identical_other_generation() {
        let selected = proxy_binding(ProtocolEra::Modern2026);
        let retained = ProxyUpstreamBinding {
            configuration_generation: selected.configuration_generation + 1,
            ..selected
        };
        let mut registry = ProxyUpstreamBindingRegistry::default();
        registry.stdio.insert(
            super::StdioBindingKey {
                route_identity: "weather-route".to_owned(),
                transport_identity: "stdio:weather".to_owned(),
                adapter_receipt_identity: "receipt-a".to_owned(),
                policy: retained.policy,
                configuration_generation: retained.configuration_generation,
            },
            retained,
        );

        let removed = registry
            .invalidate_cached_binding("weather-route", "stdio:weather", "receipt-a", selected)
            .expect("the missing exact generation has no cache entry to remove");

        assert_eq!(removed, 0);
        assert_eq!(registry.stdio.len(), 1);
        assert!(registry.stdio.values().all(|binding| *binding == retained));
    }

    #[test]
    fn live_cached_binding_invalidation_removes_only_the_exact_generation() {
        let selected = proxy_binding(ProtocolEra::Modern2026);
        let retained = ProxyUpstreamBinding {
            configuration_generation: selected.configuration_generation + 1,
            ..selected
        };
        let selected_client = ProxyClient::from_backend_with_upstream_binding(
            TestBackend::default(),
            selected,
            ProtocolEra::Modern2026.version().as_str(),
        )
        .expect("the selected modern live client is admitted");
        let retained_client = ProxyClient::from_backend_with_upstream_binding(
            TestBackend::default(),
            retained,
            ProtocolEra::Modern2026.version().as_str(),
        )
        .expect("the other generation modern live client is admitted");
        let mut registry = ProxyUpstreamBindingRegistry::default();
        registry.live_stdio.insert(
            super::LiveStdioBindingKey {
                route_identity: "weather-route".to_owned(),
                transport_identity: "stdio:weather".to_owned(),
                policy: selected.policy,
                configuration_generation: selected.configuration_generation,
            },
            selected_client,
        );
        registry.live_stdio.insert(
            super::LiveStdioBindingKey {
                route_identity: "weather-route".to_owned(),
                transport_identity: "stdio:weather".to_owned(),
                policy: retained.policy,
                configuration_generation: retained.configuration_generation,
            },
            retained_client,
        );

        let removed = registry
            .invalidate_live_cached_binding("weather-route", "stdio:weather", selected)
            .expect("the exact live binding generation can be invalidated");

        assert_eq!(removed, 1);
        assert_eq!(registry.live_stdio.len(), 1);
        assert!(
            registry
                .live_stdio
                .values()
                .all(|client| client.upstream_binding() == Some(retained))
        );
    }

    #[test]
    fn live_cached_binding_invalidation_keeps_an_identical_other_generation() {
        let selected = proxy_binding(ProtocolEra::Modern2026);
        let retained = ProxyUpstreamBinding {
            configuration_generation: selected.configuration_generation + 1,
            ..selected
        };
        let retained_client = ProxyClient::from_backend_with_upstream_binding(
            TestBackend::default(),
            retained,
            ProtocolEra::Modern2026.version().as_str(),
        )
        .expect("the other generation modern live client is admitted");
        let mut registry = ProxyUpstreamBindingRegistry::default();
        registry.live_stdio.insert(
            super::LiveStdioBindingKey {
                route_identity: "weather-route".to_owned(),
                transport_identity: "stdio:weather".to_owned(),
                policy: retained.policy,
                configuration_generation: retained.configuration_generation,
            },
            retained_client,
        );

        let removed = registry
            .invalidate_live_cached_binding("weather-route", "stdio:weather", selected)
            .expect("the missing live binding generation has no cache entry to remove");

        assert_eq!(removed, 0);
        assert_eq!(registry.live_stdio.len(), 1);
        assert!(
            registry
                .live_stdio
                .values()
                .all(|client| client.upstream_binding() == Some(retained))
        );
    }

    #[cfg(unix)]
    fn scripted_response_line(id: i64, result: serde_json::Value) -> String {
        let message =
            fastmcp_protocol::JsonRpcMessage::Response(fastmcp_protocol::JsonRpcResponse::success(
                fastmcp_protocol::RequestId::Number(id),
                result,
            ));
        let line = serde_json::to_string(&message).expect("serialize scripted response");
        assert!(
            !line.contains('\''),
            "the shell fixture requires a single-quote-free JSON line"
        );
        line
    }

    #[cfg(unix)]
    fn scripted_peer_timeout_policy() -> RequestTimeoutPolicy {
        // These fixtures emit responses immediately. Keep the former
        // five-second total ceiling while detecting an idle peer first.
        RequestTimeoutPolicy::new(Duration::from_secs(4), Duration::from_secs(5))
            .expect("valid scripted-peer timeout policy")
    }

    #[cfg(unix)]
    fn modern_discovery_response_line(server_name: &str, supported_versions: &[&str]) -> String {
        let capabilities = fastmcp_protocol::ServerDiscoverCapabilities::from_registry(
            &fastmcp_protocol::ServerBehaviorRegistry::default(),
            std::collections::BTreeMap::new(),
        )
        .expect("an empty installed behavior registry is discoverable");
        let result = fastmcp_protocol::ServerDiscoverResult::new(
            capabilities,
            fastmcp_protocol::ServerInfo {
                name: server_name.to_owned(),
                version: "1.0.0".to_owned(),
            },
            None,
            fastmcp_protocol::DiscoveryCacheHints::private_ttl_ms(0),
        );
        let mut result = serde_json::to_value(result).expect("serialize final discovery result");
        result["supportedVersions"] = serde_json::json!(supported_versions);
        scripted_response_line(1, result)
    }

    #[cfg(unix)]
    fn legacy_initialize_response_line() -> String {
        let initialize = fastmcp_protocol::InitializeResult {
            protocol_version: fastmcp_protocol::PROTOCOL_VERSION.to_owned(),
            capabilities: fastmcp_protocol::ServerCapabilities::default(),
            server_info: fastmcp_protocol::ServerInfo {
                name: "legacy-proxy-peer".to_owned(),
                version: "1.0.0".to_owned(),
            },
            instructions: None,
        };
        scripted_response_line(
            1,
            serde_json::to_value(initialize).expect("serialize legacy initialize result"),
        )
    }

    #[cfg(unix)]
    fn method_not_found_response_line() -> String {
        let message =
            fastmcp_protocol::JsonRpcMessage::Response(fastmcp_protocol::JsonRpcResponse::error(
                Some(fastmcp_protocol::RequestId::Number(1)),
                fastmcp_protocol::JsonRpcError {
                    code: (-32601).into(),
                    message: "Method not found".to_owned(),
                    data: None,
                },
            ));
        let line = serde_json::to_string(&message).expect("serialize method-not-found response");
        assert!(
            !line.contains('\''),
            "the shell fixture requires a single-quote-free JSON line"
        );
        line
    }

    #[cfg(unix)]
    fn modern_proxy_peer_script(discovery: &str, tool_result: &str) -> String {
        format!(
            r#"
IFS= read -r discovery || exit 90
case "$discovery" in *"\"method\":\"server/discover\""*) ;; *) exit 91 ;; esac
printf '%s\n' '{discovery}'
IFS= read -r tool || exit 92
case "$tool" in *"\"method\":\"tools/call\""*) ;; *) exit 93 ;; esac
printf '%s\n' '{tool_result}'
exec sleep 2
"#
        )
    }

    #[cfg(unix)]
    fn legacy_proxy_peer_script(initialize: &str, tool_result: &str) -> String {
        format!(
            r#"
IFS= read -r initialize || exit 90
case "$initialize" in *"\"method\":\"initialize\""*) ;; *) exit 91 ;; esac
printf '%s\n' '{initialize}'
IFS= read -r lifecycle || exit 92
case "$lifecycle" in *"\"method\":\"notifications/initialized\""*) ;; *) exit 93 ;; esac
IFS= read -r tool || exit 94
case "$tool" in *"\"method\":\"tools/call\""*) ;; *) exit 95 ;; esac
printf '%s\n' '{tool_result}'
exec sleep 2
"#
        )
    }

    #[cfg(unix)]
    fn malformed_modern_or_legacy_peer_script(
        malformed_discovery: &str,
        legacy_initialize: &str,
    ) -> String {
        format!(
            r#"
IFS= read -r first || exit 90
case "$first" in
    *"\"method\":\"server/discover\""*)
        printf '%s\n' '{malformed_discovery}'
        ;;
    *"\"method\":\"initialize\""*)
        printf '%s\n' '{legacy_initialize}'
        IFS= read -r lifecycle || exit 91
        case "$lifecycle" in *"\"method\":\"notifications/initialized\""*) ;; *) exit 92 ;; esac
        ;;
    *) exit 93 ;;
esac
exec sleep 2
"#
        )
    }

    #[cfg(unix)]
    fn auto_legacy_proxy_peer_script(
        discovery_refusal: &str,
        legacy_initialize: &str,
        tool_result: &str,
    ) -> String {
        format!(
            r#"
IFS= read -r first || exit 90
case "$first" in
    *"\"method\":\"server/discover\""*)
        printf '%s\n' '{discovery_refusal}'
        ;;
    *"\"method\":\"initialize\""*)
        printf '%s\n' '{legacy_initialize}'
        IFS= read -r lifecycle || exit 91
        case "$lifecycle" in *"\"method\":\"notifications/initialized\""*) ;; *) exit 92 ;; esac
        IFS= read -r tool || exit 93
        case "$tool" in *"\"method\":\"tools/call\""*) ;; *) exit 94 ;; esac
        printf '%s\n' '{tool_result}'
        ;;
    *) exit 95 ;;
esac
exec sleep 2
"#
        )
    }

    #[cfg(unix)]
    fn assert_forwarded_tool(content: Vec<Content>) {
        assert!(matches!(
            content.as_slice(),
            [Content::Text { text }] if text == "forwarded"
        ));
    }

    fn assert_forwarded_final_tool(result: CompleteResult<FinalCallToolResult>) {
        assert!(matches!(
            result.payload.content.as_slice(),
            [ContentBlock::Text { text, .. }] if text == "forwarded"
        ));
    }

    struct CapturedHttpRequest {
        head: String,
        body: Vec<u8>,
    }

    fn read_http_request(stream: &mut TcpStream) -> CapturedHttpRequest {
        let mut wire = Vec::new();
        let mut buffer = [0_u8; 4_096];
        let head_end = loop {
            let read = stream.read(&mut buffer).expect("read native HTTP request");
            assert!(read > 0, "client closed before a complete request arrived");
            wire.extend_from_slice(&buffer[..read]);
            if let Some(position) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let head = std::str::from_utf8(&wire[..head_end])
            .expect("request head must be UTF-8")
            .to_owned();
        let content_length = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .map(|value| {
                value
                    .parse::<usize>()
                    .expect("Content-Length must be numeric")
            })
            .unwrap_or(0);
        while wire.len() < head_end.saturating_add(content_length) {
            let read = stream
                .read(&mut buffer)
                .expect("read native HTTP request body");
            assert!(read > 0, "client closed before the advertised body arrived");
            wire.extend_from_slice(&buffer[..read]);
        }

        CapturedHttpRequest {
            head,
            body: wire[head_end..head_end + content_length].to_vec(),
        }
    }

    fn write_http_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
        let reason = match status {
            200 => "OK",
            202 => "Accepted",
            404 => "Not Found",
            _ => "Test Response",
        };
        write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("write native HTTP response head");
        stream
            .write_all(body)
            .expect("write native HTTP response body");
        stream.flush().expect("flush native HTTP response");
    }

    fn http_proxy_plan(
        modern_target: &str,
        legacy_sse_target: &str,
        legacy_message_target: &str,
    ) -> ClientProtocolPlan {
        ClientProtocolPlan::http(
            ProtocolPolicy::Auto,
            Some(CanonicalHttpUrl::parse(modern_target).expect("canonical modern target")),
            Some(CanonicalHttpUrl::parse(legacy_sse_target).expect("canonical legacy SSE target")),
            Some(
                CanonicalHttpUrl::parse(legacy_message_target)
                    .expect("canonical legacy message target"),
            ),
            "proxy-http-credential-partition".to_owned(),
            "proxy-http-security-partition".to_owned(),
            "proxy-http-native-h1".to_owned(),
            1,
            1,
            0,
        )
        .expect("complete Auto HTTP plan must be accepted")
    }

    fn proxy_http_client_info() -> ClientInfo {
        ClientInfo {
            name: "proxy-http-test-client".to_owned(),
            version: "1.0.0".to_owned(),
        }
    }

    fn legacy_only_http_proxy_plan(
        legacy_sse_target: &str,
        legacy_message_target: &str,
    ) -> ClientProtocolPlan {
        ClientProtocolPlan::http(
            ProtocolPolicy::LegacyOnly,
            None,
            Some(CanonicalHttpUrl::parse(legacy_sse_target).expect("canonical legacy SSE target")),
            Some(
                CanonicalHttpUrl::parse(legacy_message_target)
                    .expect("canonical legacy message target"),
            ),
            "proxy-http-legacy-callback-credential-partition".to_owned(),
            "proxy-http-legacy-callback-security-partition".to_owned(),
            "proxy-http-legacy-callback-native-h1".to_owned(),
            1,
            1,
            0,
        )
        .expect("complete legacy-only HTTP plan must be accepted")
    }

    fn legacy_http_proxy_client(
        legacy_sse_target: &str,
        legacy_message_target: &str,
        client_capabilities: ClientCapabilities,
    ) -> ProxyHttpClient {
        let cx = Cx::for_request();
        let client_info = proxy_http_client_info();
        let connection = block_on(ClientHttpConnection::connect(
            &cx,
            legacy_only_http_proxy_plan(legacy_sse_target, legacy_message_target),
            client_info.clone(),
            client_capabilities.clone(),
        ))
        .expect("legacy-only HTTP plan opens the exact legacy SSE client");
        ProxyHttpClient::new(
            ProxyUpstreamBinding {
                era: ProtocolEra::Legacy2024,
                adapter: ProxyUpstreamAdapter::LegacyHttpSse,
                policy: ProtocolPolicy::LegacyOnly,
                configuration_generation: 91,
            },
            connection,
            cx,
            client_info,
            client_capabilities,
        )
    }

    fn legacy_tools_list_names(result: CoreResult) -> Vec<String> {
        let CoreResult::Legacy(LegacyCoreResult::ToolsList(result)) = result else {
            panic!("exact legacy proxy request must retain a legacy tools/list result");
        };
        result.tools.into_iter().map(|tool| tool.name).collect()
    }

    #[test]
    fn proxy_legacy_http_refuses_one_interleaved_control_frame_past_its_bound_unchanged() {
        let mut accepted = 0;
        for _ in 0..MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES {
            admit_legacy_interleaved_control_frame(&mut accepted)
                .expect("the configured control-frame bound is admitted exactly");
        }
        let error = admit_legacy_interleaved_control_frame(&mut accepted)
            .expect_err("one additional interleaved control frame must be refused");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert_eq!(accepted, MAX_LEGACY_INTERLEAVED_CONTROL_FRAMES);
    }

    #[derive(Clone, Copy)]
    enum HttpProxyPublicPath {
        Catalog,
        Handler,
    }

    impl HttpProxyPublicPath {
        const fn name(self) -> &'static str {
            match self {
                Self::Catalog => "catalog",
                Self::Handler => "handler",
            }
        }
    }

    #[test]
    fn proxy_outbound_http_auto_modern_catalog_and_handler_use_negotiated_backend() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
        let address = listener
            .local_addr()
            .expect("read native HTTP listener address");
        let modern_target = format!("http://{address}/mcp");
        let legacy_sse_target = format!("http://{address}/legacy-sse");
        let legacy_message_target = format!("http://{address}/legacy-message");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern probe");
            let probe_request = read_http_request(&mut probe);
            write_http_response(
                &mut probe,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#,
            );

            let responses = [
                br#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[{"name":"echo","inputSchema":{"type":"object"}}],"nextCursor":"tools-page-2","ttlMs":0,"cacheScope":"private"}}"#.as_slice(),
                br#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","tools":[{"name":"echo-next","inputSchema":{"type":"object"}}],"ttlMs":0,"cacheScope":"private"}}"#.as_slice(),
                br#"{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete","resources":[{"uri":"https://example.test/one","name":"resource-one"}],"nextCursor":"resources-page-2","ttlMs":0,"cacheScope":"private"}}"#.as_slice(),
                br#"{"jsonrpc":"2.0","id":5,"result":{"resultType":"complete","resources":[{"uri":"https://example.test/two","name":"resource-two"}],"ttlMs":0,"cacheScope":"private"}}"#.as_slice(),
                br#"{"jsonrpc":"2.0","id":6,"result":{"resultType":"complete","resourceTemplates":[{"uriTemplate":"https://example.test/{city}","name":"template-one"}],"nextCursor":"templates-page-2","ttlMs":0,"cacheScope":"private"}}"#.as_slice(),
                br#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","resourceTemplates":[{"uriTemplate":"https://example.test/{region}","name":"template-two"}],"ttlMs":0,"cacheScope":"private"}}"#.as_slice(),
                br#"{"jsonrpc":"2.0","id":8,"result":{"resultType":"complete","prompts":[{"name":"prompt-one"}],"nextCursor":"prompts-page-2","ttlMs":0,"cacheScope":"private"}}"#.as_slice(),
                br#"{"jsonrpc":"2.0","id":9,"result":{"resultType":"complete","prompts":[{"name":"prompt-two"}],"ttlMs":0,"cacheScope":"private"}}"#.as_slice(),
                br#"{"jsonrpc":"2.0","id":10,"result":{"resultType":"complete","content":[{"type":"text","text":"forwarded"}]}}"#.as_slice(),
            ];
            let mut normal_requests = Vec::new();
            for response in responses {
                let (mut normal, _) = listener.accept().expect("accept modern proxy request");
                let request = read_http_request(&mut normal);
                write_http_response(&mut normal, 200, "application/json", response);
                normal_requests.push(request);
            }
            (probe_request, normal_requests)
        });
        let plan = http_proxy_plan(&modern_target, &legacy_sse_target, &legacy_message_target);
        let mut bindings = ProxyClient::upstream_binding_registry();

        let proxy = bindings
            .connect_http_with_protocol_plan(
                "modern-http-backend",
                "native-h1:modern-http-backend",
                9,
                plan.clone(),
                proxy_http_client_info(),
                ClientCapabilities::default(),
                Cx::for_request(),
            )
            .expect("recognized modern discovery must select the native modern proxy client");
        let binding = proxy.upstream_binding().expect("live binding is retained");
        assert_eq!(binding.era(), ProtocolEra::Modern2026);
        assert_eq!(binding.adapter(), super::ProxyUpstreamAdapter::ModernHttp);
        assert_eq!(binding.policy(), ProtocolPolicy::Auto);
        let catalog = proxy
            .catalog_typed()
            .expect("typed public proxy catalog uses the negotiated modern HTTP era");
        assert_eq!(
            catalog.era().expect("one negotiated catalog era"),
            ProtocolEra::Modern2026
        );
        let ProxyToolCatalog::Final(tools) = catalog.tools else {
            panic!("modern HTTP catalog must retain its exact final tool model");
        };
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            ["echo", "echo-next"],
            "the proxy retains every modern tools/list page"
        );
        let ProxyResourceCatalog::Final(resources) = catalog.resources else {
            panic!("modern HTTP catalog must retain its exact final resource model");
        };
        assert_eq!(
            resources
                .iter()
                .map(|resource| resource.name.as_str())
                .collect::<Vec<_>>(),
            ["resource-one", "resource-two"],
            "the proxy retains every modern resources/list page"
        );
        let ProxyResourceTemplateCatalog::Final(resource_templates) = catalog.resource_templates
        else {
            panic!("modern HTTP catalog must retain exact final resource templates");
        };
        assert_eq!(
            resource_templates
                .iter()
                .map(|template| template.name.as_str())
                .collect::<Vec<_>>(),
            ["template-one", "template-two"],
            "the proxy retains every modern resources/templates/list page"
        );
        let ProxyPromptCatalog::Final(prompts) = catalog.prompts else {
            panic!("modern HTTP catalog must retain its exact final prompt model");
        };
        assert_eq!(
            prompts
                .iter()
                .map(|prompt| prompt.name.as_str())
                .collect::<Vec<_>>(),
            ["prompt-one", "prompt-two"],
            "the proxy retains every modern prompts/list page"
        );
        let final_tool = tools
            .first()
            .expect("modern HTTP catalog returns the remote tool");
        assert_eq!(final_tool.name, "echo");
        // The handler must forward under the DISCOVERED catalog tool's
        // external name, so it is built from that tool, not a local fixture.
        let handler = ProxyToolHandler::from_final(final_tool.clone(), proxy.clone())
            .expect("the discovered final tool builds a proxy handler");
        assert_forwarded_final_tool(
            handler
                .call_final(
                    &McpContext::new(Cx::for_testing(), 700),
                    serde_json::json!({"value": 1}),
                )
                .expect("the final proxy handler preserves the modern HTTP result"),
        );

        let cached = bindings
            .connect_http_with_protocol_plan(
                "modern-http-backend",
                "native-h1:modern-http-backend",
                9,
                plan,
                proxy_http_client_info(),
                ClientCapabilities::default(),
                Cx::for_request(),
            )
            .expect("the exact backend returns its cached selected client");
        assert_eq!(cached.upstream_binding(), Some(binding));
        assert_eq!(bindings.live_http.len(), 1);

        let (probe, normal) = server.join().expect("modern HTTP server must join");
        assert!(probe.head.starts_with("POST /mcp HTTP/1.1\r\n"));
        assert!(probe.head.contains("MCP-Protocol-Version: 2026-07-28\r\n"));
        assert!(probe.head.contains("Mcp-Method: server/discover\r\n"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&probe.body).expect("modern probe JSON")["params"]
                ["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
            "proxy-http-test-client"
        );
        let expected_methods = [
            "tools/list",
            "tools/list",
            "resources/list",
            "resources/list",
            "resources/templates/list",
            "resources/templates/list",
            "prompts/list",
            "prompts/list",
            "tools/call",
        ];
        assert_eq!(normal.len(), expected_methods.len());
        for (request, method) in normal.iter().zip(expected_methods) {
            assert!(request.head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert!(
                request
                    .head
                    .contains("MCP-Protocol-Version: 2026-07-28\r\n")
            );
            assert!(request.head.contains(&format!("Mcp-Method: {method}\r\n")));
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&request.body)
                    .expect("modern normal request JSON")["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
                serde_json::json!({})
            );
        }
        for (request, cursor) in normal.iter().zip([
            None,
            Some("tools-page-2"),
            None,
            Some("resources-page-2"),
            None,
            Some("templates-page-2"),
            None,
            Some("prompts-page-2"),
            None,
        ]) {
            let parameters = serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("modern paged catalog request JSON")["params"]
                .clone();
            assert_eq!(
                parameters.get("cursor").and_then(serde_json::Value::as_str),
                cursor,
                "only second modern catalog pages carry their predecessor cursor"
            );
        }
        let call = serde_json::from_slice::<serde_json::Value>(&normal[8].body)
            .expect("modern handler request JSON");
        assert_eq!(call["method"], "tools/call");
        assert_eq!(call["params"]["name"], "echo");
    }

    #[test]
    fn proxy_outbound_http_auto_legacy_catalog_and_handler_use_negotiated_backend() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
        let address = listener
            .local_addr()
            .expect("read native HTTP listener address");
        let modern_target = format!("http://{address}/mcp");
        let legacy_sse_target = format!("http://{address}/legacy-sse");
        let legacy_message_target = format!("http://{address}/legacy-message?session=proxy");
        let expected_message_target = legacy_message_target.clone();
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept disposable modern probe");
            let probe_request = read_http_request(&mut probe);
            write_http_response(&mut probe, 404, "text/plain", b"");

            let (mut sse, _) = listener.accept().expect("accept exact legacy SSE GET");
            let sse_request = read_http_request(&mut sse);
            let mut body = format!("event: endpoint\ndata: {expected_message_target}\n\n");
            body.push_str(concat!(
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-proxy-peer\",\"version\":\"1.0.0\"}}}\n\n",
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"echo\",\"inputSchema\":{}}]}}\n\n",
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resources\":[]}}\n\n",
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{\"resourceTemplates\":[]}}\n\n",
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"prompts\":[]}}\n\n",
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"forwarded\"}]}}\n\n"
            ));
            write_http_response(&mut sse, 200, "text/event-stream", body.as_bytes());

            let mut posts = Vec::new();
            for _ in 0..7 {
                let (mut post, _) = listener.accept().expect("accept advertised legacy POST");
                let request = read_http_request(&mut post);
                write_http_response(&mut post, 202, "application/json", b"");
                posts.push(request);
            }
            (probe_request, sse_request, posts)
        });
        let plan = http_proxy_plan(&modern_target, &legacy_sse_target, &legacy_message_target);
        let mut bindings = ProxyClient::upstream_binding_registry();

        let proxy = bindings
            .connect_http_with_protocol_plan(
                "legacy-http-backend",
                "native-h1:legacy-http-backend",
                10,
                plan.clone(),
                proxy_http_client_info(),
                ClientCapabilities::default(),
                Cx::for_request(),
            )
            .expect("only the authorized disposable refusal may select legacy SSE");
        let binding = proxy.upstream_binding().expect("live binding is retained");
        assert_eq!(binding.era(), ProtocolEra::Legacy2024);
        assert_eq!(
            binding.adapter(),
            super::ProxyUpstreamAdapter::LegacyHttpSse
        );
        assert_eq!(binding.policy(), ProtocolPolicy::Auto);
        let catalog = proxy
            .catalog()
            .expect("public proxy catalog uses legacy SSE");
        let handler = ProxyToolHandler::new(
            catalog
                .tools
                .first()
                .expect("legacy HTTP catalog returns the remote tool")
                .clone(),
            proxy.clone(),
        );
        assert_forwarded_tool(
            handler
                .call(
                    &McpContext::new(Cx::for_testing(), 701),
                    serde_json::json!({"value": 1}),
                )
                .expect("public proxy handler forwards over legacy SSE"),
        );

        let cached = bindings
            .connect_http_with_protocol_plan(
                "legacy-http-backend",
                "native-h1:legacy-http-backend",
                10,
                plan,
                proxy_http_client_info(),
                ClientCapabilities::default(),
                Cx::for_request(),
            )
            .expect("the exact legacy backend returns its cached selected client");
        assert_eq!(cached.upstream_binding(), Some(binding));
        assert_eq!(bindings.live_http.len(), 1);

        let (probe, sse, posts) = server.join().expect("legacy HTTP server must join");
        assert!(probe.head.starts_with("POST /mcp HTTP/1.1\r\n"));
        assert!(probe.head.contains("MCP-Protocol-Version: 2026-07-28\r\n"));
        assert!(sse.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
        assert!(sse.head.contains("Accept: text/event-stream\r\n"));
        assert!(!sse.head.contains("MCP-Protocol-Version:"));
        let expected_methods = [
            "initialize",
            "notifications/initialized",
            "tools/list",
            "resources/list",
            "resources/templates/list",
            "prompts/list",
            "tools/call",
        ];
        assert_eq!(posts.len(), expected_methods.len());
        for (request, method) in posts.iter().zip(expected_methods) {
            assert!(
                request
                    .head
                    .starts_with("POST /legacy-message?session=proxy HTTP/1.1\r\n")
            );
            assert!(request.head.contains("Content-Type: application/json\r\n"));
            assert!(!request.head.contains("MCP-Protocol-Version:"));
            let message = serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("legacy proxy request JSON");
            assert_eq!(message["method"], method);
        }
        let initialize = serde_json::from_slice::<serde_json::Value>(&posts[0].body)
            .expect("legacy initialize JSON");
        assert_eq!(
            initialize["params"]["clientInfo"]["name"],
            "proxy-http-test-client"
        );
    }

    #[test]
    fn proxy_legacy_http_replies_to_authorized_reverse_requests_without_losing_follow_up() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
        let address = listener
            .local_addr()
            .expect("read native HTTP listener address");
        let legacy_sse_target = format!("http://{address}/legacy-sse");
        let legacy_message_target = format!("http://{address}/legacy-message?session=reverse");
        let expected_message_target = legacy_message_target.clone();
        let server = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept exact legacy SSE GET");
            let sse_request = read_http_request(&mut sse);
            // Only the endpoint line interpolates; the literal JSON events
            // stay outside format! so their braces need no escaping.
            let body = format!("event: endpoint\ndata: {expected_message_target}\n\n")
                + concat!(
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-proxy-peer\",\"version\":\"1.0.0\"}}}\n\n",
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":80,\"method\":\"sampling/createMessage\",\"params\":{\"messages\":[],\"maxTokens\":1}}\n\n",
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":81,\"method\":\"roots/list\",\"params\":{}}\n\n",
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":82,\"method\":\"elicitation/create\",\"params\":{}}\n\n",
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n\n",
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[]}}\n\n",
                );
            write_http_response(&mut sse, 200, "text/event-stream", body.as_bytes());

            let mut posts = Vec::new();
            for _ in 0..7 {
                let (mut post, _) = listener.accept().expect("accept legacy proxy POST");
                let request = read_http_request(&mut post);
                write_http_response(&mut post, 202, "application/json", b"");
                posts.push(request);
            }
            (sse_request, posts)
        });
        let mut proxy = legacy_http_proxy_client(
            &legacy_sse_target,
            &legacy_message_target,
            ClientCapabilities {
                sampling: Some(fastmcp_protocol::SamplingCapability {}),
                elicitation: None,
                roots: Some(fastmcp_protocol::RootsCapability {
                    list_changed: false,
                }),
            },
        );

        assert!(
            legacy_tools_list_names(
                proxy
                    .request_result(fastmcp_protocol::methods::TOOLS_LIST, serde_json::json!({}))
                    .expect("authorized reverse requests retain their upstream result"),
            )
            .is_empty()
        );
        assert!(
            legacy_tools_list_names(
                proxy
                    .request_result(fastmcp_protocol::methods::TOOLS_LIST, serde_json::json!({}))
                    .expect("the following request remains aligned after reverse replies"),
            )
            .is_empty()
        );

        let (sse, posts) = server
            .join()
            .expect("legacy reverse-request server must join");
        assert!(sse.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
        let messages: Vec<serde_json::Value> = posts
            .iter()
            .map(|post| {
                serde_json::from_slice(&post.body).expect("legacy proxy POST remains JSON-RPC")
            })
            .collect();
        assert_eq!(
            messages
                .iter()
                .map(|message| message["method"].as_str())
                .collect::<Vec<_>>(),
            vec![
                Some("initialize"),
                Some("notifications/initialized"),
                Some("tools/list"),
                None,
                None,
                None,
                Some("tools/list"),
            ],
        );
        assert_eq!(
            messages[0]["params"]["capabilities"]["sampling"],
            serde_json::json!({})
        );
        assert_eq!(
            messages[0]["params"]["capabilities"]["roots"],
            serde_json::json!({})
        );
        assert_eq!(messages[3]["id"], serde_json::json!(80));
        assert_eq!(messages[3]["error"]["code"], serde_json::json!(-32603));
        assert_eq!(messages[4]["id"], serde_json::json!(81));
        assert_eq!(messages[4]["result"], serde_json::json!({"roots": []}));
        assert_eq!(messages[5]["id"], serde_json::json!(82));
        assert_eq!(messages[5]["error"]["code"], serde_json::json!(-32601));
        assert_eq!(messages[6]["id"], serde_json::json!(3));
    }

    #[test]
    fn proxy_legacy_http_rejects_sampling_when_only_its_capability_is_removed() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
        let address = listener
            .local_addr()
            .expect("read native HTTP listener address");
        let legacy_sse_target = format!("http://{address}/legacy-sse");
        let legacy_message_target = format!("http://{address}/legacy-message?session=reverse");
        let expected_message_target = legacy_message_target.clone();
        let server = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept exact legacy SSE GET");
            let sse_request = read_http_request(&mut sse);
            // Only the endpoint line interpolates; the literal JSON events
            // stay outside format! so their braces need no escaping.
            let body = format!("event: endpoint\ndata: {expected_message_target}\n\n")
                + concat!(
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-proxy-peer\",\"version\":\"1.0.0\"}}}\n\n",
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":80,\"method\":\"sampling/createMessage\",\"params\":{\"messages\":[],\"maxTokens\":1}}\n\n",
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":81,\"method\":\"roots/list\",\"params\":{}}\n\n",
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":82,\"method\":\"elicitation/create\",\"params\":{}}\n\n",
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n\n",
                    "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[]}}\n\n",
                );
            write_http_response(&mut sse, 200, "text/event-stream", body.as_bytes());

            let mut posts = Vec::new();
            for _ in 0..7 {
                let (mut post, _) = listener
                    .accept()
                    .expect("accept unchanged legacy proxy POST");
                let request = read_http_request(&mut post);
                write_http_response(&mut post, 202, "application/json", b"");
                posts.push(request);
            }
            (sse_request, posts)
        });
        let mut proxy = legacy_http_proxy_client(
            &legacy_sse_target,
            &legacy_message_target,
            ClientCapabilities {
                sampling: None,
                elicitation: None,
                roots: Some(fastmcp_protocol::RootsCapability {
                    list_changed: false,
                }),
            },
        );

        assert!(
            legacy_tools_list_names(
                proxy
                    .request_result(fastmcp_protocol::methods::TOOLS_LIST, serde_json::json!({}))
                    .expect("the sampling refusal must not replace the active result"),
            )
            .is_empty()
        );
        assert!(
            legacy_tools_list_names(
                proxy
                    .request_result(fastmcp_protocol::methods::TOOLS_LIST, serde_json::json!({}))
                    .expect("the sampling refusal must not alter the next request"),
            )
            .is_empty()
        );

        let (sse, posts) = server
            .join()
            .expect("legacy reverse-request server must join");
        assert!(sse.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
        let messages: Vec<serde_json::Value> = posts
            .iter()
            .map(|post| {
                serde_json::from_slice(&post.body).expect("legacy proxy POST remains JSON-RPC")
            })
            .collect();
        assert!(
            messages[0]["params"]["capabilities"]
                .get("sampling")
                .is_none()
        );
        assert_eq!(
            messages[0]["params"]["capabilities"]["roots"],
            serde_json::json!({})
        );
        assert_eq!(messages[3]["id"], serde_json::json!(80));
        assert_eq!(messages[3]["error"]["code"], serde_json::json!(-32601));
        assert_eq!(messages[4]["id"], serde_json::json!(81));
        assert_eq!(messages[4]["result"], serde_json::json!({"roots": []}));
        assert_eq!(messages[5]["id"], serde_json::json!(82));
        assert_eq!(messages[5]["error"]["code"], serde_json::json!(-32601));
        assert_eq!(messages[6]["id"], serde_json::json!(3));
    }

    #[test]
    fn proxy_legacy_http_cancellation_matches_only_the_active_request() {
        for (name, cancellation_request_id, first_is_cancelled) in
            [("matching", "2e0", true), ("unrelated", "99", false)]
        {
            let listener = TcpListener::bind("127.0.0.1:0")
                .expect("bind native HTTP listener for cancellation case");
            let address = listener
                .local_addr()
                .expect("read native HTTP listener address");
            let legacy_sse_target = format!("http://{address}/legacy-sse");
            let legacy_message_target =
                format!("http://{address}/legacy-message?session=cancellation-{name}");
            let expected_message_target = legacy_message_target.clone();
            let server = thread::spawn(move || {
                let (mut sse, _) = listener.accept().expect("accept exact legacy SSE GET");
                let sse_request = read_http_request(&mut sse);
                // Interpolating lines are formatted individually (with literal
                // braces escaped); pure-literal events stay outside format!.
                let body = format!("event: endpoint\ndata: {expected_message_target}\n\n")
                    + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-proxy-peer\",\"version\":\"1.0.0\"}}}\n\n"
                    + &format!(
                        "event: message\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{{\"requestId\":{cancellation_request_id}}}}}\n\n"
                    )
                    + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"active\",\"inputSchema\":{}}]}}\n\n"
                    + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[{\"name\":\"follow-up\",\"inputSchema\":{}}]}}\n\n";
                write_http_response(&mut sse, 200, "text/event-stream", body.as_bytes());

                let mut posts = Vec::new();
                for _ in 0..4 {
                    let (mut post, _) = listener.accept().expect("accept legacy proxy POST");
                    let request = read_http_request(&mut post);
                    write_http_response(&mut post, 202, "application/json", b"");
                    posts.push(request);
                }
                (sse_request, posts)
            });
            let mut proxy = legacy_http_proxy_client(
                &legacy_sse_target,
                &legacy_message_target,
                ClientCapabilities::default(),
            );

            let first =
                proxy.request_result(fastmcp_protocol::methods::TOOLS_LIST, serde_json::json!({}));
            if first_is_cancelled {
                assert_eq!(
                    first
                        .expect_err("only the matching cancellation retires the active request")
                        .code,
                    McpErrorCode::RequestCancelled,
                );
            } else {
                assert_eq!(
                    legacy_tools_list_names(
                        first.expect("an unrelated cancellation must not alter the active request"),
                    ),
                    vec!["active"],
                );
            }
            assert_eq!(
                legacy_tools_list_names(
                    proxy
                        .request_result(
                            fastmcp_protocol::methods::TOOLS_LIST,
                            serde_json::json!({}),
                        )
                        .expect("the subsequent exact-2024 request remains aligned"),
                ),
                vec!["follow-up"],
            );

            let (sse, posts) = server.join().expect("legacy cancellation server must join");
            assert!(sse.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            let messages: Vec<serde_json::Value> = posts
                .iter()
                .map(|post| {
                    serde_json::from_slice(&post.body).expect("legacy proxy POST remains JSON-RPC")
                })
                .collect();
            assert_eq!(messages[0]["method"], serde_json::json!("initialize"));
            assert_eq!(
                messages[1]["method"],
                serde_json::json!("notifications/initialized")
            );
            assert_eq!(messages[2]["id"], serde_json::json!(2));
            assert_eq!(messages[3]["id"], serde_json::json!(3));
        }
    }

    #[test]
    fn proxy_outbound_http_auto_rejects_one_field_legacy_endpoint_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
        let address = listener
            .local_addr()
            .expect("read native HTTP listener address");
        let modern_target = format!("http://{address}/mcp");
        let legacy_sse_target = format!("http://{address}/legacy-sse");
        let legacy_message_target = format!("http://{address}/legacy-message?session=expected");
        let advertised_message_target = format!("http://{address}/legacy-message?session=altered");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept disposable modern probe");
            let probe_request = read_http_request(&mut probe);
            write_http_response(&mut probe, 404, "text/plain", b"");

            let (mut sse, _) = listener.accept().expect("accept exact legacy SSE GET");
            let sse_request = read_http_request(&mut sse);
            let body = format!("event: endpoint\ndata: {advertised_message_target}\n\n");
            write_http_response(&mut sse, 200, "text/event-stream", body.as_bytes());
            (probe_request, sse_request)
        });
        let mut bindings = ProxyClient::upstream_binding_registry();

        let error = bindings
            .connect_http_with_protocol_plan(
                "legacy-endpoint-mismatch",
                "native-h1:legacy-endpoint-mismatch",
                16,
                http_proxy_plan(&modern_target, &legacy_sse_target, &legacy_message_target),
                proxy_http_client_info(),
                ClientCapabilities::default(),
                Cx::for_request(),
            )
            .expect_err("changing only the advertised session value must fail closed");

        assert_eq!(error.code, McpErrorCode::InternalError);
        assert!(
            bindings.live_http.is_empty(),
            "a rejected advertised endpoint must not install a legacy cache entry"
        );

        let (probe, sse) = server.join().expect("legacy mismatch server must join");
        assert!(probe.head.starts_with("POST /mcp HTTP/1.1\r\n"));
        assert!(probe.head.contains("Mcp-Method: server/discover\r\n"));
        assert!(sse.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
        assert!(sse.head.contains("Accept: text/event-stream\r\n"));
    }

    #[test]
    fn proxy_http_cache_does_not_share_one_field_client_identity_change() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
        let address = listener
            .local_addr()
            .expect("read native HTTP listener address");
        let modern_target = format!("http://{address}/mcp");
        let legacy_sse_target = format!("http://{address}/legacy-sse");
        let legacy_message_target = format!("http://{address}/legacy-message");
        let server = thread::spawn(move || {
            let mut probes = Vec::new();
            for _ in 0..2 {
                let (mut probe, _) = listener.accept().expect("accept modern probe");
                let request = read_http_request(&mut probe);
                write_http_response(
                    &mut probe,
                    200,
                    "application/json",
                    br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#,
                );
                probes.push(request);
            }
            probes
        });
        let plan = http_proxy_plan(&modern_target, &legacy_sse_target, &legacy_message_target);
        let mut bindings = ProxyClient::upstream_binding_registry();
        let first = bindings
            .connect_http_with_protocol_plan(
                "identity-cache-backend",
                "native-h1:identity-cache-backend",
                12,
                plan.clone(),
                proxy_http_client_info(),
                ClientCapabilities::default(),
                Cx::for_request(),
            )
            .expect("first identity opens the modern upstream");
        let second = bindings
            .connect_http_with_protocol_plan(
                "identity-cache-backend",
                "native-h1:identity-cache-backend",
                12,
                plan,
                ClientInfo {
                    name: "proxy-http-test-client".to_owned(),
                    version: "1.0.1".to_owned(),
                },
                ClientCapabilities::default(),
                Cx::for_request(),
            )
            .expect("one clientInfo field change opens a separate modern upstream");

        assert_eq!(bindings.live_http.len(), 2);
        assert_eq!(first.upstream_binding(), second.upstream_binding());
        let probes = server.join().expect("identity cache server must join");
        let versions = probes
            .iter()
            .map(|probe| {
                serde_json::from_slice::<serde_json::Value>(&probe.body).expect("modern probe JSON")
                    ["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]["version"]
                    .as_str()
                    .expect("client identity version")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(versions, vec!["1.0.0".to_owned(), "1.0.1".to_owned()]);
    }

    #[test]
    fn proxy_http_cache_does_not_share_one_field_client_capability_change() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
        let address = listener
            .local_addr()
            .expect("read native HTTP listener address");
        let modern_target = format!("http://{address}/mcp");
        let legacy_sse_target = format!("http://{address}/legacy-sse");
        let legacy_message_target = format!("http://{address}/legacy-message");
        let server = thread::spawn(move || {
            let mut probes = Vec::new();
            for _ in 0..2 {
                let (mut probe, _) = listener.accept().expect("accept modern probe");
                let request = read_http_request(&mut probe);
                write_http_response(
                    &mut probe,
                    200,
                    "application/json",
                    br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#,
                );
                probes.push(request);
            }
            probes
        });
        let plan = http_proxy_plan(&modern_target, &legacy_sse_target, &legacy_message_target);
        let mut bindings = ProxyClient::upstream_binding_registry();
        bindings
            .connect_http_with_protocol_plan(
                "capability-cache-backend",
                "native-h1:capability-cache-backend",
                13,
                plan.clone(),
                proxy_http_client_info(),
                ClientCapabilities::default(),
                Cx::for_request(),
            )
            .expect("first capability set opens the modern upstream");
        bindings
            .connect_http_with_protocol_plan(
                "capability-cache-backend",
                "native-h1:capability-cache-backend",
                13,
                plan,
                proxy_http_client_info(),
                ClientCapabilities {
                    roots: Some(fastmcp_protocol::RootsCapability { list_changed: true }),
                    ..ClientCapabilities::default()
                },
                Cx::for_request(),
            )
            .expect("one clientCapabilities field change opens a separate modern upstream");

        assert_eq!(bindings.live_http.len(), 2);
        let probes = server.join().expect("capability cache server must join");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&probes[0].body)
                .expect("first modern probe JSON")["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
            serde_json::json!({})
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&probes[1].body)
                .expect("second modern probe JSON")["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
            serde_json::json!({"roots": {"listChanged": true}})
        );
    }

    #[test]
    fn proxy_http_modern_empty_acknowledgement_rejects_correlated_catalog_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
        let address = listener
            .local_addr()
            .expect("read native HTTP listener address");
        let modern_target = format!("http://{address}/mcp");
        let legacy_sse_target = format!("http://{address}/legacy-sse");
        let legacy_message_target = format!("http://{address}/legacy-message");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern probe");
            let probe_request = read_http_request(&mut probe);
            write_http_response(
                &mut probe,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#,
            );

            let (mut request, _) = listener
                .accept()
                .expect("accept correlated modern catalog request");
            let catalog_request = read_http_request(&mut request);
            request
                .write_all(
                    b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("write content-type-free notification acknowledgement");
            request
                .flush()
                .expect("flush content-type-free notification acknowledgement");
            (probe_request, catalog_request)
        });
        let plan = http_proxy_plan(&modern_target, &legacy_sse_target, &legacy_message_target);
        let mut bindings = ProxyClient::upstream_binding_registry();
        let proxy = bindings
            .connect_http_with_protocol_plan(
                "modern-empty-acknowledgement-backend",
                "native-h1:modern-empty-acknowledgement-backend",
                14,
                plan,
                proxy_http_client_info(),
                ClientCapabilities::default(),
                Cx::for_request(),
            )
            .expect("modern discovery opens the proxy backend");

        let error = proxy.catalog().expect_err(
            "a notification acknowledgement cannot satisfy a correlated catalog request",
        );
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(error.message.contains("notification acknowledgement"));

        let (probe, catalog_request) = server.join().expect("modern HTTP server must join");
        assert!(probe.head.contains("Mcp-Method: server/discover\r\n"));
        assert!(catalog_request.head.contains("Mcp-Method: tools/list\r\n"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&catalog_request.body)
                .expect("modern catalog request must be JSON")["id"],
            serde_json::json!(2),
        );
    }

    #[test]
    fn proxy_http_modern_response_id_mismatch_rejects_public_catalog_and_handler() {
        for path in [HttpProxyPublicPath::Catalog, HttpProxyPublicPath::Handler] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
            let address = listener
                .local_addr()
                .expect("read native HTTP listener address");
            let modern_target = format!("http://{address}/mcp");
            let legacy_sse_target = format!("http://{address}/legacy-sse");
            let legacy_message_target = format!("http://{address}/legacy-message");
            let responses = match path {
                HttpProxyPublicPath::Catalog => vec![br#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","tools":[{"name":"echo","inputSchema":{"type":"object"}}],"ttlMs":0,"cacheScope":"private"}}"#.to_vec()],
                HttpProxyPublicPath::Handler => vec![
                    br#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[{"name":"echo","inputSchema":{"type":"object"}}],"ttlMs":0,"cacheScope":"private"}}"#.to_vec(),
                    br#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","resources":[],"ttlMs":0,"cacheScope":"private"}}"#.to_vec(),
                    br#"{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete","resourceTemplates":[],"ttlMs":0,"cacheScope":"private"}}"#.to_vec(),
                    br#"{"jsonrpc":"2.0","id":5,"result":{"resultType":"complete","prompts":[],"ttlMs":0,"cacheScope":"private"}}"#.to_vec(),
                    br#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","content":[{"type":"text","text":"forwarded"}]}}"#.to_vec(),
                ],
            };
            let expected_methods: Vec<&str> = match path {
                HttpProxyPublicPath::Catalog => vec!["tools/list"],
                HttpProxyPublicPath::Handler => vec![
                    "tools/list",
                    "resources/list",
                    "resources/templates/list",
                    "prompts/list",
                    "tools/call",
                ],
            };
            let server = thread::spawn(move || {
                let (mut probe, _) = listener.accept().expect("accept modern probe");
                let probe_request = read_http_request(&mut probe);
                write_http_response(
                    &mut probe,
                    200,
                    "application/json",
                    br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#,
                );

                let mut requests = Vec::new();
                for response in responses {
                    let (mut stream, _) = listener.accept().expect("accept public proxy request");
                    let request = read_http_request(&mut stream);
                    write_http_response(&mut stream, 200, "application/json", &response);
                    requests.push(request);
                }
                (probe_request, requests)
            });
            let plan = http_proxy_plan(&modern_target, &legacy_sse_target, &legacy_message_target);
            let mut bindings = ProxyClient::upstream_binding_registry();
            let route = format!("modern-id-mismatch-{}", path.name());
            let transport = format!("native-h1:{route}");
            let proxy = bindings
                .connect_http_with_protocol_plan(
                    &route,
                    &transport,
                    14,
                    plan.clone(),
                    proxy_http_client_info(),
                    ClientCapabilities::default(),
                    Cx::for_request(),
                )
                .expect("modern discovery opens the public proxy backend");
            let binding = proxy.upstream_binding().expect("live binding is retained");

            let error = match path {
                HttpProxyPublicPath::Catalog => proxy
                    .catalog()
                    .expect_err("changing only the catalog response ID must fail closed"),
                HttpProxyPublicPath::Handler => {
                    let catalog = proxy
                        .catalog()
                        .expect("only the later handler response ID is mismatched");
                    assert!(catalog.tools.is_empty());
                    assert_eq!(catalog.final_tools.len(), 1);
                    ProxyToolHandler::new(proxy_test_tool(), proxy.clone())
                        .call(
                            &McpContext::new(Cx::for_testing(), 710),
                            serde_json::json!({}),
                        )
                        .expect_err("changing only the handler response ID must fail closed")
                }
            };

            assert_eq!(error.code, McpErrorCode::InvalidRequest);
            assert_eq!(bindings.live_http.len(), 1);
            let cached = bindings
                .connect_http_with_protocol_plan(
                    &route,
                    &transport,
                    14,
                    plan,
                    proxy_http_client_info(),
                    ClientCapabilities::default(),
                    Cx::for_request(),
                )
                .expect("a response-ID refusal must not alter the selected cache binding");
            assert_eq!(cached.upstream_binding(), Some(binding));
            assert_eq!(bindings.live_http.len(), 1);

            let (probe, requests) = server.join().expect("modern ID-mismatch server must join");
            assert!(probe.head.contains("Mcp-Method: server/discover\r\n"));
            assert_eq!(requests.len(), expected_methods.len());
            for (index, (request, method)) in requests.iter().zip(expected_methods).enumerate() {
                assert!(request.head.contains(&format!("Mcp-Method: {method}\r\n")));
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&request.body)
                        .expect("modern public proxy request JSON")["id"],
                    serde_json::json!(index as i64 + 2)
                );
            }
        }
    }

    #[test]
    fn proxy_http_legacy_response_id_mismatch_rejects_public_catalog_and_handler() {
        for path in [HttpProxyPublicPath::Catalog, HttpProxyPublicPath::Handler] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
            let address = listener
                .local_addr()
                .expect("read native HTTP listener address");
            let modern_target = format!("http://{address}/mcp");
            let legacy_sse_target = format!("http://{address}/legacy-sse");
            let legacy_message_target = format!("http://{address}/legacy-message?session=proof");
            let expected_message_target = legacy_message_target.clone();
            let initialize_result = serde_json::to_value(fastmcp_protocol::InitializeResult {
                protocol_version: fastmcp_protocol::PROTOCOL_VERSION.to_owned(),
                capabilities: fastmcp_protocol::ServerCapabilities::default(),
                server_info: fastmcp_protocol::ServerInfo {
                    name: "legacy-id-mismatch-peer".to_owned(),
                    version: "1.0.0".to_owned(),
                },
                instructions: None,
            })
            .expect("serialize legacy initialize result");
            let tools_result = serde_json::json!({
                "tools": [{"name": "echo", "inputSchema": {}}]
            });
            let messages = match path {
                HttpProxyPublicPath::Catalog => vec![(1, initialize_result), (3, tools_result)],
                HttpProxyPublicPath::Handler => vec![
                    (1, initialize_result),
                    (2, tools_result),
                    (3, serde_json::json!({"resources": []})),
                    (4, serde_json::json!({"resourceTemplates": []})),
                    (5, serde_json::json!({"prompts": []})),
                    (
                        7,
                        serde_json::json!({"content": [{"type": "text", "text": "forwarded"}]}),
                    ),
                ],
            };
            let expected_methods: Vec<&str> = match path {
                HttpProxyPublicPath::Catalog => {
                    vec!["initialize", "notifications/initialized", "tools/list"]
                }
                HttpProxyPublicPath::Handler => vec![
                    "initialize",
                    "notifications/initialized",
                    "tools/list",
                    "resources/list",
                    "resources/templates/list",
                    "prompts/list",
                    "tools/call",
                ],
            };
            let expected_post_count = expected_methods.len();
            let expected_request_ids: Vec<Option<i64>> = match path {
                HttpProxyPublicPath::Catalog => vec![Some(1), None, Some(2)],
                HttpProxyPublicPath::Handler => {
                    vec![Some(1), None, Some(2), Some(3), Some(4), Some(5), Some(6)]
                }
            };
            let server = thread::spawn(move || {
                let (mut probe, _) = listener.accept().expect("accept disposable modern probe");
                let probe_request = read_http_request(&mut probe);
                write_http_response(&mut probe, 404, "text/plain", b"");

                let (mut sse, _) = listener.accept().expect("accept exact legacy SSE GET");
                let sse_request = read_http_request(&mut sse);
                let mut body = format!("event: endpoint\ndata: {expected_message_target}\n\n");
                for (id, result) in messages {
                    let message = fastmcp_protocol::JsonRpcMessage::Response(
                        fastmcp_protocol::JsonRpcResponse::success(
                            fastmcp_protocol::RequestId::Number(id),
                            result,
                        ),
                    );
                    body.push_str("event: message\ndata: ");
                    body.push_str(&serde_json::to_string(&message).expect("serialize SSE message"));
                    body.push_str("\n\n");
                }
                write_http_response(&mut sse, 200, "text/event-stream", body.as_bytes());

                let mut posts = Vec::new();
                for _ in 0..expected_post_count {
                    let (mut post, _) = listener.accept().expect("accept advertised legacy POST");
                    let request = read_http_request(&mut post);
                    write_http_response(&mut post, 202, "application/json", b"");
                    posts.push(request);
                }
                (probe_request, sse_request, posts)
            });
            let plan = http_proxy_plan(&modern_target, &legacy_sse_target, &legacy_message_target);
            let mut bindings = ProxyClient::upstream_binding_registry();
            let route = format!("legacy-id-mismatch-{}", path.name());
            let transport = format!("native-h1:{route}");
            let proxy = bindings
                .connect_http_with_protocol_plan(
                    &route,
                    &transport,
                    15,
                    plan.clone(),
                    proxy_http_client_info(),
                    ClientCapabilities::default(),
                    Cx::for_request(),
                )
                .expect("authorized modern refusal opens the public legacy proxy backend");
            let binding = proxy.upstream_binding().expect("live binding is retained");

            let error = match path {
                HttpProxyPublicPath::Catalog => proxy
                    .catalog()
                    .expect_err("changing only the legacy catalog response ID must fail closed"),
                HttpProxyPublicPath::Handler => {
                    let catalog = proxy
                        .catalog()
                        .expect("only the later legacy handler response ID is mismatched");
                    ProxyToolHandler::new(
                        catalog
                            .tools
                            .first()
                            .expect("catalog returns the remote tool before the mismatch")
                            .clone(),
                        proxy.clone(),
                    )
                    .call(
                        &McpContext::new(Cx::for_testing(), 711),
                        serde_json::json!({}),
                    )
                    .expect_err("changing only the legacy handler response ID must fail closed")
                }
            };

            assert_eq!(error.code, McpErrorCode::InvalidRequest);
            assert_eq!(bindings.live_http.len(), 1);
            let cached = bindings
                .connect_http_with_protocol_plan(
                    &route,
                    &transport,
                    15,
                    plan,
                    proxy_http_client_info(),
                    ClientCapabilities::default(),
                    Cx::for_request(),
                )
                .expect("a legacy response-ID refusal must not alter the selected cache binding");
            assert_eq!(cached.upstream_binding(), Some(binding));
            assert_eq!(bindings.live_http.len(), 1);

            let (probe, sse, posts) = server.join().expect("legacy ID-mismatch server must join");
            assert!(probe.head.contains("Mcp-Method: server/discover\r\n"));
            assert!(sse.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
            assert_eq!(posts.len(), expected_methods.len());
            for ((request, method), expected_id) in
                posts.iter().zip(expected_methods).zip(expected_request_ids)
            {
                assert!(
                    request
                        .head
                        .starts_with("POST /legacy-message?session=proof HTTP/1.1\r\n")
                );
                let message = serde_json::from_slice::<serde_json::Value>(&request.body)
                    .expect("legacy public proxy request JSON");
                assert_eq!(message["method"], method);
                match expected_id {
                    Some(expected_id) => assert_eq!(message["id"], serde_json::json!(expected_id)),
                    None => assert!(message.get("id").is_none()),
                }
            }
        }
    }

    #[test]
    fn proxy_outbound_http_auto_contradictory_modern_peer_never_falls_back_or_caches() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
        let address = listener
            .local_addr()
            .expect("read native HTTP listener address");
        let modern_target = format!("http://{address}/mcp");
        let legacy_sse_target = format!("http://{address}/legacy-sse");
        let legacy_message_target = format!("http://{address}/legacy-message");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept modern probe");
            let request = read_http_request(&mut probe);
            // This is the modern-positive discovery response with only its
            // advertised version changed to the exact legacy revision.
            write_http_response(
                &mut probe,
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2024-11-05"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#,
            );
            listener
                .set_nonblocking(true)
                .expect("allow bounded legacy-connection observation");
            let deadline = Instant::now() + Duration::from_millis(100);
            loop {
                match listener.accept() {
                    Ok(_) => panic!("a contradictory modern response must not open legacy SSE"),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("observe unintended legacy connection: {error}"),
                }
            }
            request
        });
        let mut bindings = ProxyClient::upstream_binding_registry();
        let error = bindings
            .connect_http_with_protocol_plan(
                "contradictory-http-backend",
                "native-h1:contradictory-http-backend",
                11,
                http_proxy_plan(&modern_target, &legacy_sse_target, &legacy_message_target),
                proxy_http_client_info(),
                ClientCapabilities::default(),
                Cx::for_request(),
            )
            .err()
            .expect("a contradictory modern discovery response must not downgrade to legacy");

        assert_eq!(error.code, McpErrorCode::InternalError);
        assert!(bindings.live_http.is_empty());
        let probe = server.join().expect("contradictory HTTP server must join");
        assert!(probe.head.starts_with("POST /mcp HTTP/1.1\r\n"));
        assert!(probe.head.contains("MCP-Protocol-Version: 2026-07-28\r\n"));
        assert!(probe.head.contains("Mcp-Method: server/discover\r\n"));
    }

    #[cfg(unix)]
    #[test]
    fn proxy_outbound_modern_only_selects_live_client_and_forwards_tool() {
        let discovery = modern_discovery_response_line("modern-proxy-peer", &["2026-07-28"]);
        let tool_result = scripted_response_line(
            2,
            serde_json::json!({"content": [{"type": "text", "text": "forwarded"}]}),
        );
        let script = modern_proxy_peer_script(&discovery, &tool_result);
        let mut bindings = ProxyClient::upstream_binding_registry();

        let proxy = bindings
            .connect_stdio_with_protocol_plan(
                "modern-route",
                "stdio:modern-peer",
                1,
                "sh",
                &["-c", script.as_str()],
                fastmcp_client::ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
                Cx::for_testing(),
            )
            .expect("ModernOnly connects a live modern client");

        let binding = proxy.upstream_binding().expect("live binding is retained");
        assert_eq!(binding.era(), ProtocolEra::Modern2026);
        assert_eq!(binding.adapter(), super::ProxyUpstreamAdapter::ModernStdio);
        assert_eq!(binding.policy(), ProtocolPolicy::ModernOnly);
        assert_forwarded_final_tool(
            proxy
                .call_tool_final(
                    &McpContext::new(Cx::for_testing(), 100),
                    "echo",
                    serde_json::json!({}),
                )
                .expect("the selected live client preserves its final result"),
        );
        assert_eq!(bindings.live_stdio.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn proxy_outbound_auto_selects_live_modern_client_and_forwards_tool() {
        let discovery = modern_discovery_response_line("auto-proxy-peer", &["2026-07-28"]);
        let tool_result = scripted_response_line(
            2,
            serde_json::json!({"content": [{"type": "text", "text": "forwarded"}]}),
        );
        let script = modern_proxy_peer_script(&discovery, &tool_result);
        let mut bindings = ProxyClient::upstream_binding_registry();

        let proxy = bindings
            .connect_stdio_with_protocol_plan(
                "auto-route",
                "stdio:auto-peer",
                2,
                "sh",
                &["-c", script.as_str()],
                fastmcp_client::ClientProtocolPlan::stdio(ProtocolPolicy::Auto),
                Cx::for_testing(),
            )
            .expect("Auto retains its live modern selection");

        let binding = proxy.upstream_binding().expect("live binding is retained");
        assert_eq!(binding.era(), ProtocolEra::Modern2026);
        assert_eq!(binding.policy(), ProtocolPolicy::Auto);
        assert_forwarded_final_tool(
            proxy
                .call_tool_final(
                    &McpContext::new(Cx::for_testing(), 101),
                    "echo",
                    serde_json::json!({}),
                )
                .expect("Auto preserves ordinary final results through its live client"),
        );
        assert_eq!(bindings.live_stdio.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn proxy_outbound_auto_pins_live_stdio_era_per_upstream() {
        let discovery = modern_discovery_response_line("pinned-auto-proxy-peer", &["2026-07-28"]);
        let first_tool_result = scripted_response_line(
            2,
            serde_json::json!({"content": [{"type": "text", "text": "first"}]}),
        );
        let second_tool_result = scripted_response_line(
            3,
            serde_json::json!({"content": [{"type": "text", "text": "second"}]}),
        );
        let script = format!(
            r#"
IFS= read -r discovery || exit 90
case "$discovery" in *"\"method\":\"server/discover\""*) ;; *) exit 91 ;; esac
printf '%s\n' '{discovery}'
IFS= read -r first_tool || exit 92
case "$first_tool" in *"\"method\":\"tools/call\""*) ;; *) exit 93 ;; esac
printf '%s\n' '{first_tool_result}'
IFS= read -r second_tool || exit 94
case "$second_tool" in *"\"method\":\"tools/call\""*) ;; *) exit 95 ;; esac
printf '%s\n' '{second_tool_result}'
exec sleep 2
"#
        );
        let mut bindings = ProxyClient::upstream_binding_registry();
        let first = bindings
            .connect_stdio_with_protocol_plan(
                "pinned-auto-route",
                "stdio:pinned-auto-peer",
                22,
                "sh",
                &["-c", script.as_str()],
                ClientProtocolPlan::stdio(ProtocolPolicy::Auto),
                Cx::for_testing(),
            )
            .expect("the real Auto discovery selects the modern upstream");
        let selected = first
            .upstream_binding()
            .expect("the selected era is retained");
        let second = bindings
            .connect_stdio_with_protocol_plan(
                "pinned-auto-route",
                "stdio:pinned-auto-peer",
                22,
                "sh",
                &["-c", script.as_str()],
                ClientProtocolPlan::stdio(ProtocolPolicy::Auto),
                Cx::for_testing(),
            )
            .expect("the same immutable upstream reuses its pinned selection");

        assert_eq!(selected.era(), ProtocolEra::Modern2026);
        assert_eq!(selected.policy(), ProtocolPolicy::Auto);
        assert_eq!(second.upstream_binding(), Some(selected));
        assert!(matches!(
            first
                .call_tool_final(
                    &McpContext::new(Cx::for_testing(), 112),
                    "echo",
                    serde_json::json!({}),
                )
                .expect("the first request uses the live modern client")
                .payload
                .content
                .as_slice(),
            [ContentBlock::Text { text, .. }] if text == "first"
        ));
        assert!(matches!(
            second
                .call_tool_final(
                    &McpContext::new(Cx::for_testing(), 113),
                    "echo",
                    serde_json::json!({}),
                )
                .expect("the cached proxy advances the same selected client")
                .payload
                .content
                .as_slice(),
            [ContentBlock::Text { text, .. }] if text == "second"
        ));
        assert_eq!(bindings.live_stdio.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn proxy_outbound_auto_authorized_refusal_selects_live_legacy_client_and_forwards_tool() {
        let discovery_refusal = method_not_found_response_line();
        let initialize = legacy_initialize_response_line();
        let tool_result = scripted_response_line(
            2,
            serde_json::json!({"content": [{"type": "text", "text": "forwarded"}]}),
        );
        let script = auto_legacy_proxy_peer_script(&discovery_refusal, &initialize, &tool_result);
        let mut bindings = ProxyClient::upstream_binding_registry();

        let proxy = bindings
            .connect_stdio_with_protocol_plan(
                "auto-legacy-route",
                "stdio:auto-legacy-peer",
                3,
                "sh",
                &["-c", script.as_str()],
                fastmcp_client::ClientProtocolPlan::stdio(ProtocolPolicy::Auto),
                Cx::for_testing(),
            )
            .expect("Auto selects exact legacy only after an authorized modern refusal");

        let binding = proxy.upstream_binding().expect("live binding is retained");
        assert_eq!(binding.era(), ProtocolEra::Legacy2024);
        assert_eq!(binding.adapter(), super::ProxyUpstreamAdapter::LegacyStdio);
        assert_eq!(binding.policy(), ProtocolPolicy::Auto);
        assert_forwarded_tool(
            proxy
                .call_tool(
                    &McpContext::new(Cx::for_testing(), 102),
                    "echo",
                    serde_json::json!({}),
                )
                .expect("Auto forwards through its selected live legacy client"),
        );
        assert_eq!(bindings.live_stdio.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn proxy_outbound_legacy_only_selects_live_client_and_forwards_tool() {
        let initialize = legacy_initialize_response_line();
        let tool_result = scripted_response_line(
            2,
            serde_json::json!({"content": [{"type": "text", "text": "forwarded"}]}),
        );
        let script = legacy_proxy_peer_script(&initialize, &tool_result);
        let mut bindings = ProxyClient::upstream_binding_registry();

        let proxy = bindings
            .connect_stdio_with_protocol_plan(
                "legacy-route",
                "stdio:legacy-peer",
                4,
                "sh",
                &["-c", script.as_str()],
                fastmcp_client::ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
                Cx::for_testing(),
            )
            .expect("LegacyOnly connects a live exact-2024 client");

        let binding = proxy.upstream_binding().expect("live binding is retained");
        assert_eq!(binding.era(), ProtocolEra::Legacy2024);
        assert_eq!(binding.adapter(), super::ProxyUpstreamAdapter::LegacyStdio);
        assert_eq!(binding.policy(), ProtocolPolicy::LegacyOnly);
        assert_forwarded_tool(
            proxy
                .call_tool(
                    &McpContext::new(Cx::for_testing(), 103),
                    "echo",
                    serde_json::json!({}),
                )
                .expect("LegacyOnly forwards ordinary requests through its live client"),
        );
        assert_eq!(bindings.live_stdio.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn proxy_outbound_auto_rejects_one_field_contradictory_live_stdio_era() {
        // This differs from the modern live-positive fixture only in the
        // advertised discovery version: exact legacy cannot be accepted as a
        // successful modern discovery or authorize a fallback.
        let contradictory_discovery =
            modern_discovery_response_line("auto-proxy-peer", &["2024-11-05"]);
        let legacy_initialize = legacy_initialize_response_line();
        let script =
            malformed_modern_or_legacy_peer_script(&contradictory_discovery, &legacy_initialize);
        let mut bindings = ProxyClient::upstream_binding_registry();

        let error = bindings
            .connect_stdio_with_protocol_plan(
                "auto-malformed-route",
                "stdio:auto-malformed-peer",
                5,
                "sh",
                &["-c", script.as_str()],
                fastmcp_client::ClientProtocolPlan::stdio(ProtocolPolicy::Auto),
                Cx::for_testing(),
            )
            .err()
            .expect("a contradictory modern success must not start the available legacy peer");

        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(
            bindings.live_stdio.is_empty(),
            "only successful live selections are cacheable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn proxy_catalog_initializes_real_client_before_capability_checks() {
        let initialize = fastmcp_protocol::InitializeResult {
            protocol_version: fastmcp_protocol::PROTOCOL_VERSION.to_string(),
            capabilities: fastmcp_protocol::ServerCapabilities {
                tools: Some(fastmcp_protocol::ToolsCapability::default()),
                resources: Some(fastmcp_protocol::ResourcesCapability::default()),
                prompts: Some(fastmcp_protocol::PromptsCapability::default()),
                ..fastmcp_protocol::ServerCapabilities::default()
            },
            server_info: fastmcp_protocol::ServerInfo {
                name: "proxy-script".to_string(),
                version: "1.0.0".to_string(),
            },
            instructions: None,
        };
        let initialize = scripted_response_line(
            1,
            serde_json::to_value(initialize).expect("serialize initialize result"),
        );
        let tools = scripted_response_line(2, serde_json::json!({"tools": []}));
        let resources = scripted_response_line(3, serde_json::json!({"resources": []}));
        let templates = scripted_response_line(4, serde_json::json!({"resourceTemplates": []}));
        let prompts = scripted_response_line(5, serde_json::json!({"prompts": []}));
        // Act as a minimal real peer: require every request in protocol order
        // before releasing its response. A watchdog bounds failures where the
        // client stops writing while the peer is waiting for the next line.
        let script = format!(
            r#"
peer_pid=$$
(sleep 8; kill -TERM "$peer_pid" 2>/dev/null) >/dev/null 2>&1 &
watchdog_pid=$!
trap 'kill "$watchdog_pid" 2>/dev/null || true' EXIT
trap 'exit 99' HUP INT TERM
expect_method() (
    IFS= read -r line || exit 90
    case "$line" in
        *"\"method\":\"$1\""*) ;;
        *) exit 91 ;;
    esac
)
expect_method initialize || exit $?
printf '%s\n' '{initialize}'
expect_method notifications/initialized || exit $?
expect_method tools/list || exit $?
printf '%s\n' '{tools}'
expect_method resources/list || exit $?
printf '%s\n' '{resources}'
expect_method resources/templates/list || exit $?
printf '%s\n' '{templates}'
expect_method prompts/list || exit $?
printf '%s\n' '{prompts}'
kill "$watchdog_pid" 2>/dev/null || true
wait "$watchdog_pid" 2>/dev/null || true
exec sleep 2
"#
        );
        let cx = Cx::for_testing();
        let mut client = fastmcp_client::ClientBuilder::new()
            .auto_initialize(true)
            .request_timeout_policy(scripted_peer_timeout_policy())
            .connect_stdio_with_cx("sh", &["-c", script.as_str()], &cx)
            .expect("spawn scripted auto-initializing client");
        assert!(!client.is_initialized());

        let catalog = ProxyCatalog::from_client(&mut client)
            .expect("catalog initializes and enumerates advertised capabilities");

        assert!(client.is_initialized());
        assert!(catalog.tools.is_empty());
        assert!(catalog.resources.is_empty());
        assert!(catalog.resource_templates.is_empty());
        assert!(catalog.prompts.is_empty());
        client.close().expect("close proxy catalog client");
    }

    #[cfg(unix)]
    #[test]
    fn proxy_catalog_initializes_before_skipping_unadvertised_lists() {
        let initialize = fastmcp_protocol::InitializeResult {
            protocol_version: fastmcp_protocol::PROTOCOL_VERSION.to_string(),
            capabilities: fastmcp_protocol::ServerCapabilities::default(),
            server_info: fastmcp_protocol::ServerInfo {
                name: "proxy-script".to_string(),
                version: "1.0.0".to_string(),
            },
            instructions: None,
        };
        let initialize = scripted_response_line(
            1,
            serde_json::to_value(initialize).expect("serialize initialize result"),
        );
        let script = format!("printf '%s\\n' '{initialize}'; exec sleep 2");
        let cx = Cx::for_testing();
        let mut client = fastmcp_client::ClientBuilder::new()
            .auto_initialize(true)
            .request_timeout_policy(scripted_peer_timeout_policy())
            .connect_stdio_with_cx("sh", &["-c", script.as_str()], &cx)
            .expect("spawn scripted auto-initializing client");

        let catalog = ProxyCatalog::from_client(&mut client)
            .expect("unadvertised lists are skipped only after initialization");

        assert!(client.is_initialized());
        assert!(catalog.tools.is_empty());
        assert!(catalog.resources.is_empty());
        assert!(catalog.resource_templates.is_empty());
        assert!(catalog.prompts.is_empty());
        client.close().expect("close proxy catalog client");
    }

    #[test]
    fn proxy_catalog_collects_definitions() {
        let backend = TestBackend {
            tools: vec![Tool {
                name: "tool".to_string(),
                description: None,
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }],
            resources: vec![Resource {
                uri: "test://resource".to_string(),
                name: "resource".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }],
            prompts: vec![Prompt {
                name: "prompt".to_string(),
                description: None,
                arguments: Vec::new(),
                icon: None,
                version: None,
                tags: vec![],
            }],
            ..TestBackend::default()
        };
        let mut backend = backend;
        let catalog = ProxyCatalog::from_backend(&mut backend).expect("catalog");
        assert_eq!(catalog.tools.len(), 1);
        assert_eq!(catalog.resources.len(), 1);
        assert_eq!(catalog.prompts.len(), 1);
    }

    #[test]
    fn proxy_tool_handler_forwards_calls() {
        let state = Arc::new(Mutex::new(TestState::default()));
        let backend = TestBackend {
            tools: vec![Tool {
                name: "tool".to_string(),
                description: None,
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }],
            state: Arc::clone(&state),
            ..TestBackend::default()
        };
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyToolHandler::new(
            Tool {
                name: "tool".to_string(),
                description: None,
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            },
            proxy,
        );

        let ctx = McpContext::new(Cx::for_testing(), 1);
        let args = serde_json::json!({"value": 1});
        let result = handler.call(&ctx, args.clone()).expect("call ok");
        assert_eq!(result.len(), 1);

        let guard = state.lock().expect("state lock poisoned");
        let (name, recorded_args) = guard
            .last_tool
            .as_ref()
            .expect("tool call recorded")
            .clone();
        assert_eq!(name, "tool");
        assert_eq!(recorded_args, args);
    }

    #[test]
    fn proxy_prompt_handler_forwards_calls() {
        let state = Arc::new(Mutex::new(TestState::default()));
        let backend = TestBackend {
            prompts: vec![Prompt {
                name: "prompt".to_string(),
                description: None,
                arguments: Vec::new(),
                icon: None,
                version: None,
                tags: vec![],
            }],
            state: Arc::clone(&state),
            ..TestBackend::default()
        };
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyPromptHandler::new(
            Prompt {
                name: "prompt".to_string(),
                description: None,
                arguments: Vec::new(),
                icon: None,
                version: None,
                tags: vec![],
            },
            proxy,
        );

        let ctx = McpContext::new(Cx::for_testing(), 1);
        let mut args = HashMap::new();
        args.insert("key".to_string(), "value".to_string());
        let result = handler.get(&ctx, args.clone()).expect("get ok");
        assert_eq!(result.len(), 1);

        let guard = state.lock().expect("state lock poisoned");
        let (name, recorded_args) = guard
            .last_prompt
            .as_ref()
            .expect("prompt call recorded")
            .clone();
        assert_eq!(name, "prompt");
        assert_eq!(recorded_args, args);
    }

    // =========================================================================
    // Prefixed Proxy Handler Tests (for as_proxy)
    // =========================================================================

    #[test]
    fn prefixed_tool_handler_uses_correct_names() {
        let state = Arc::new(Mutex::new(TestState::default()));
        let backend = TestBackend {
            tools: vec![Tool {
                name: "query".to_string(),
                description: Some("Execute a query".to_string()),
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }],
            state: Arc::clone(&state),
            ..TestBackend::default()
        };
        let proxy = ProxyClient::from_backend(backend);

        // Create handler with prefix "db"
        let handler = ProxyToolHandler::with_prefix(
            Tool {
                name: "query".to_string(),
                description: Some("Execute a query".to_string()),
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            },
            "db",
            proxy,
        );

        // Definition should have prefixed name
        let def = handler.definition();
        assert_eq!(def.name, "db/query");
        assert_eq!(def.description, Some("Execute a query".to_string()));

        // Call should forward with original name
        let ctx = McpContext::new(Cx::for_testing(), 1);
        let args = serde_json::json!({"sql": "SELECT 1"});
        handler.call(&ctx, args.clone()).expect("call ok");

        let guard = state.lock().expect("state lock poisoned");
        let (forwarded_name, _) = guard.last_tool.as_ref().expect("tool called").clone();
        assert_eq!(forwarded_name, "query"); // Original name, not prefixed
    }

    #[test]
    fn prefixed_prompt_handler_uses_correct_names() {
        let state = Arc::new(Mutex::new(TestState::default()));
        let backend = TestBackend {
            prompts: vec![Prompt {
                name: "greeting".to_string(),
                description: Some("A greeting prompt".to_string()),
                arguments: Vec::new(),
                icon: None,
                version: None,
                tags: vec![],
            }],
            state: Arc::clone(&state),
            ..TestBackend::default()
        };
        let proxy = ProxyClient::from_backend(backend);

        // Create handler with prefix "templates"
        let handler = ProxyPromptHandler::with_prefix(
            Prompt {
                name: "greeting".to_string(),
                description: Some("A greeting prompt".to_string()),
                arguments: Vec::new(),
                icon: None,
                version: None,
                tags: vec![],
            },
            "templates",
            proxy,
        );

        // Definition should have prefixed name
        let def = handler.definition();
        assert_eq!(def.name, "templates/greeting");
        assert_eq!(def.description, Some("A greeting prompt".to_string()));

        // Call should forward with original name
        let ctx = McpContext::new(Cx::for_testing(), 1);
        let args = HashMap::new();
        handler.get(&ctx, args).expect("get ok");

        let guard = state.lock().expect("state lock poisoned");
        let (forwarded_name, _) = guard.last_prompt.as_ref().expect("prompt called").clone();
        assert_eq!(forwarded_name, "greeting"); // Original name, not prefixed
    }

    #[test]
    fn prefixed_resource_handler_uses_correct_uri() {
        use super::ProxyResourceHandler;
        use crate::handler::ResourceHandler;

        let backend = TestBackend {
            resources: vec![Resource {
                uri: "file://data".to_string(),
                name: "Data File".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }],
            ..TestBackend::default()
        };
        let proxy = ProxyClient::from_backend(backend);

        // Create handler with prefix "storage"
        let handler = ProxyResourceHandler::with_prefix(
            Resource {
                uri: "file://data".to_string(),
                name: "Data File".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            },
            "storage",
            proxy,
        );

        // Definition should have prefixed URI
        let def = handler.definition();
        assert_eq!(def.uri, "storage/file://data");
        assert_eq!(def.name, "Data File");
    }

    // =========================================================================
    // ProxyCatalog Edge Cases
    // =========================================================================

    #[test]
    fn proxy_catalog_empty_backend() {
        let mut backend = TestBackend::default();
        let catalog = ProxyCatalog::from_backend(&mut backend).expect("catalog");
        assert!(catalog.tools.is_empty());
        assert!(catalog.resources.is_empty());
        assert!(catalog.resource_templates.is_empty());
        assert!(catalog.prompts.is_empty());
    }

    #[test]
    fn proxy_catalog_default_is_empty() {
        let catalog = ProxyCatalog::default();
        assert!(catalog.tools.is_empty());
        assert!(catalog.resources.is_empty());
        assert!(catalog.resource_templates.is_empty());
        assert!(catalog.prompts.is_empty());
    }

    #[test]
    fn proxy_catalog_multiple_items() {
        let mut backend = TestBackend {
            tools: vec![
                Tool {
                    name: "t1".to_string(),
                    description: None,
                    input_schema: serde_json::json!({}),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                    annotations: None,
                },
                Tool {
                    name: "t2".to_string(),
                    description: None,
                    input_schema: serde_json::json!({}),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                    annotations: None,
                },
            ],
            prompts: vec![
                Prompt {
                    name: "p1".to_string(),
                    description: None,
                    arguments: Vec::new(),
                    icon: None,
                    version: None,
                    tags: vec![],
                },
                Prompt {
                    name: "p2".to_string(),
                    description: None,
                    arguments: Vec::new(),
                    icon: None,
                    version: None,
                    tags: vec![],
                },
            ],
            ..TestBackend::default()
        };
        let catalog = ProxyCatalog::from_backend(&mut backend).expect("catalog");
        assert_eq!(catalog.tools.len(), 2);
        assert_eq!(catalog.prompts.len(), 2);
    }

    // =========================================================================
    // ProxyClient Tests
    // =========================================================================

    #[test]
    fn proxy_client_clone_shares_backend() {
        let state = Arc::new(Mutex::new(TestState::default()));
        let backend = TestBackend {
            tools: vec![Tool {
                name: "shared".to_string(),
                description: None,
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }],
            state: Arc::clone(&state),
            ..TestBackend::default()
        };
        let proxy1 = ProxyClient::from_backend(backend);
        let proxy2 = proxy1.clone();

        // Both clones should reach the same backend
        let catalog1 = proxy1.catalog().expect("catalog1");
        let catalog2 = proxy2.catalog().expect("catalog2");
        assert_eq!(catalog1.tools.len(), catalog2.tools.len());
    }

    #[test]
    fn proxy_client_catalog_fetches_all() {
        let backend = TestBackend {
            tools: vec![Tool {
                name: "t".to_string(),
                description: None,
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }],
            resources: vec![Resource {
                uri: "test://r".to_string(),
                name: "r".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }],
            prompts: vec![Prompt {
                name: "p".to_string(),
                description: None,
                arguments: Vec::new(),
                icon: None,
                version: None,
                tags: vec![],
            }],
            ..TestBackend::default()
        };
        let proxy = ProxyClient::from_backend(backend);
        let catalog = proxy.catalog().expect("catalog");
        assert_eq!(catalog.tools.len(), 1);
        assert_eq!(catalog.resources.len(), 1);
        assert_eq!(catalog.prompts.len(), 1);
    }

    // =========================================================================
    // ProxyResourceHandler Tests
    // =========================================================================

    #[test]
    fn proxy_resource_handler_read_forwards_to_backend() {
        use super::ProxyResourceHandler;
        use crate::handler::ResourceHandler;

        let backend = TestBackend::default();
        let state = Arc::clone(&backend.state);
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyResourceHandler::new(
            Resource {
                uri: "test://resource".to_string(),
                name: "Test".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            },
            proxy,
        );

        let ctx = McpContext::new(Cx::for_testing(), 1);
        let result = handler.read(&ctx).expect("read ok");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, Some("resource".to_string()));
        assert_eq!(
            state.lock().expect("state lock poisoned").last_resource,
            Some("test://resource".to_string())
        );
    }

    #[test]
    fn proxy_resource_handler_no_template_by_default() {
        use super::ProxyResourceHandler;
        use crate::handler::ResourceHandler;

        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyResourceHandler::new(
            Resource {
                uri: "test://x".to_string(),
                name: "x".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            },
            proxy,
        );
        assert!(handler.template().is_none());
    }

    #[test]
    fn proxy_resource_handler_from_template() {
        use super::ProxyResourceHandler;
        use crate::handler::ResourceHandler;
        use fastmcp_protocol::ResourceTemplate;

        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let template = ResourceTemplate {
            uri_template: "file://{path}".to_string(),
            name: "File".to_string(),
            description: Some("A file resource".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
            version: None,
            tags: vec![],
        };
        let handler = ProxyResourceHandler::from_template(template.clone(), proxy);

        // Definition should mirror the template
        let def = handler.definition();
        assert_eq!(def.uri, "file://{path}");
        assert_eq!(def.name, "File");
        assert_eq!(def.description, Some("A file resource".to_string()));
        assert_eq!(def.mime_type, Some("text/plain".to_string()));

        // Template should be available
        let tmpl = handler.template().expect("has template");
        assert_eq!(tmpl.uri_template, "file://{path}");
    }

    #[test]
    fn proxy_resource_handler_from_template_with_prefix() {
        use super::ProxyResourceHandler;
        use crate::handler::ResourceHandler;
        use fastmcp_protocol::ResourceTemplate;

        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let template = ResourceTemplate {
            uri_template: "file://{path}".to_string(),
            name: "File".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let handler = ProxyResourceHandler::from_template_with_prefix(template, "storage", proxy);

        // Definition should have prefixed URI template
        let def = handler.definition();
        assert_eq!(def.uri, "storage/file://{path}");

        // Template should also be prefixed
        let tmpl = handler.template().expect("has template");
        assert_eq!(tmpl.uri_template, "storage/file://{path}");
    }

    // =========================================================================
    // Error Propagation Tests
    // =========================================================================

    /// A backend that always returns errors.
    struct FailingBackend;

    impl ProxyBackend for FailingBackend {
        fn list_tools(&mut self) -> fastmcp_core::McpResult<Vec<Tool>> {
            Err(fastmcp_core::McpError::internal_error("tool list failed"))
        }

        fn list_resources(&mut self) -> fastmcp_core::McpResult<Vec<Resource>> {
            Err(fastmcp_core::McpError::internal_error(
                "resource list failed",
            ))
        }

        fn list_resource_templates(
            &mut self,
        ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceTemplate>> {
            Err(fastmcp_core::McpError::internal_error(
                "template list failed",
            ))
        }

        fn list_prompts(&mut self) -> fastmcp_core::McpResult<Vec<Prompt>> {
            Err(fastmcp_core::McpError::internal_error("prompt list failed"))
        }

        fn call_tool(
            &mut self,
            _name: &str,
            _arguments: serde_json::Value,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Err(fastmcp_core::McpError::internal_error("tool call failed"))
        }

        fn call_tool_with_progress(
            &mut self,
            _name: &str,
            _arguments: serde_json::Value,
            _on_progress: super::ProgressCallback<'_>,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Err(fastmcp_core::McpError::internal_error("tool call failed"))
        }

        fn read_resource(&mut self, _uri: &str) -> fastmcp_core::McpResult<Vec<ResourceContent>> {
            Err(fastmcp_core::McpError::internal_error(
                "resource read failed",
            ))
        }

        fn get_prompt(
            &mut self,
            _name: &str,
            _arguments: HashMap<String, String>,
        ) -> fastmcp_core::McpResult<Vec<PromptMessage>> {
            Err(fastmcp_core::McpError::internal_error("prompt get failed"))
        }
    }

    #[test]
    fn proxy_catalog_propagates_tool_list_error() {
        let mut backend = FailingBackend;
        let result = ProxyCatalog::from_backend(&mut backend);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("tool list failed"));
    }

    #[test]
    fn proxy_tool_handler_propagates_call_error() {
        let proxy = ProxyClient::from_backend(FailingBackend);
        let handler = ProxyToolHandler::new(
            Tool {
                name: "fail".to_string(),
                description: None,
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            },
            proxy,
        );

        let ctx = McpContext::new(Cx::for_testing(), 1);
        let result = handler.call(&ctx, serde_json::json!({}));
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("tool call failed"));
    }

    #[test]
    fn proxy_resource_handler_propagates_read_error() {
        use super::ProxyResourceHandler;
        use crate::handler::ResourceHandler;

        let proxy = ProxyClient::from_backend(FailingBackend);
        let handler = ProxyResourceHandler::new(
            Resource {
                uri: "test://fail".to_string(),
                name: "Fail".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            },
            proxy,
        );

        let ctx = McpContext::new(Cx::for_testing(), 1);
        let result = handler.read(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("resource read failed"));
    }

    #[test]
    fn proxy_prompt_handler_propagates_get_error() {
        let proxy = ProxyClient::from_backend(FailingBackend);
        let handler = ProxyPromptHandler::new(
            Prompt {
                name: "fail".to_string(),
                description: None,
                arguments: Vec::new(),
                icon: None,
                version: None,
                tags: vec![],
            },
            proxy,
        );

        let ctx = McpContext::new(Cx::for_testing(), 1);
        let result = handler.get(&ctx, HashMap::new());
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("prompt get failed"));
    }

    // =========================================================================
    // resource_from_template Helper
    // =========================================================================

    #[test]
    fn resource_from_template_copies_all_fields() {
        use fastmcp_protocol::ResourceTemplate;

        let template = ResourceTemplate {
            uri_template: "db://{table}/{id}".to_string(),
            name: "Database Record".to_string(),
            description: Some("A database record".to_string()),
            mime_type: Some("application/json".to_string()),
            icon: None,
            version: Some("1.0.0".to_string()),
            tags: vec!["db".to_string()],
        };
        let resource = super::resource_from_template(&template);
        assert_eq!(resource.uri, "db://{table}/{id}");
        assert_eq!(resource.name, "Database Record");
        assert_eq!(resource.description, Some("A database record".to_string()));
        assert_eq!(resource.mime_type, Some("application/json".to_string()));
        assert_eq!(resource.version, Some("1.0.0".to_string()));
        assert_eq!(resource.tags, vec!["db".to_string()]);
    }

    // =========================================================================
    // ProxyCatalog trait derives
    // =========================================================================

    #[test]
    fn proxy_catalog_debug() {
        let catalog = ProxyCatalog {
            tools: vec![Tool {
                name: "dbg-tool".to_string(),
                description: None,
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }],
            ..ProxyCatalog::default()
        };
        let debug = format!("{:?}", catalog);
        assert!(debug.contains("ProxyCatalog"));
        assert!(debug.contains("dbg-tool"));
    }

    #[test]
    fn proxy_catalog_clone() {
        let catalog = ProxyCatalog {
            tools: vec![Tool {
                name: "cloned".to_string(),
                description: None,
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }],
            ..ProxyCatalog::default()
        };
        let cloned = catalog.clone();
        assert_eq!(cloned.tools.len(), 1);
        assert_eq!(cloned.tools[0].name, "cloned");
    }

    // =========================================================================
    // ProxyResourceHandler.read_with_uri
    // =========================================================================

    #[test]
    fn proxy_resource_handler_read_with_uri_uses_params() {
        use super::ProxyResourceHandler;
        use crate::handler::ResourceHandler;

        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyResourceHandler::new(
            Resource {
                uri: "test://r".to_string(),
                name: "R".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            },
            proxy,
        );

        let ctx = McpContext::new(Cx::for_testing(), 1);
        let params = HashMap::new();
        let result = handler
            .read_with_uri(&ctx, "test://r", &params)
            .expect("read ok");
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn proxy_resource_handler_read_with_uri_strips_prefix() {
        use super::ProxyResourceHandler;
        use crate::handler::ResourceHandler;

        let backend = TestBackend::default();
        let state = Arc::clone(&backend.state);
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyResourceHandler::with_prefix(
            Resource {
                uri: "file://data".to_string(),
                name: "Data".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            },
            "ext",
            proxy,
        );

        let ctx = McpContext::new(Cx::for_testing(), 1);
        let params = HashMap::new();
        // URI with prefix should still work (prefix gets stripped)
        let result = handler
            .read_with_uri(&ctx, "ext/file://data", &params)
            .expect("read ok");
        assert_eq!(result.len(), 1);
        assert_eq!(
            state.lock().expect("state lock poisoned").last_resource,
            Some("file://data".to_string())
        );
    }

    #[test]
    fn proxy_resource_handler_read_with_uri_no_prefix_match() {
        use super::ProxyResourceHandler;
        use crate::handler::ResourceHandler;

        let backend = TestBackend::default();
        let state = Arc::clone(&backend.state);
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyResourceHandler::new(
            Resource {
                uri: "test://r".to_string(),
                name: "R".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            },
            proxy,
        );

        let ctx = McpContext::new(Cx::for_testing(), 1);
        let params = HashMap::new();
        // URI without prefix match - used as-is
        let result = handler
            .read_with_uri(&ctx, "other://uri", &params)
            .expect("read ok");
        assert_eq!(result.len(), 1);
        assert_eq!(
            state.lock().expect("state lock poisoned").last_resource,
            Some("other://uri".to_string())
        );
    }

    // =========================================================================
    // ProxyToolHandler.definition
    // =========================================================================

    #[test]
    fn proxy_tool_handler_definition_returns_clone() {
        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyToolHandler::new(
            Tool {
                name: "def-tool".to_string(),
                description: Some("desc".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec!["tag1".to_string()],
                annotations: None,
            },
            proxy,
        );

        let def = handler.definition();
        assert_eq!(def.name, "def-tool");
        assert_eq!(def.description, Some("desc".to_string()));
        assert_eq!(def.tags, vec!["tag1".to_string()]);
    }

    // =========================================================================
    // ProxyPromptHandler.definition
    // =========================================================================

    #[test]
    fn proxy_prompt_handler_definition_returns_clone() {
        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyPromptHandler::new(
            Prompt {
                name: "def-prompt".to_string(),
                description: Some("A prompt".to_string()),
                arguments: Vec::new(),
                icon: None,
                version: None,
                tags: vec!["tag2".to_string()],
            },
            proxy,
        );

        let def = handler.definition();
        assert_eq!(def.name, "def-prompt");
        assert_eq!(def.description, Some("A prompt".to_string()));
        assert_eq!(def.tags, vec!["tag2".to_string()]);
    }

    // =========================================================================
    // ProxyClient.read_resource and get_prompt
    // =========================================================================

    #[test]
    fn proxy_client_read_resource() {
        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let ctx = McpContext::new(Cx::for_testing(), 1);
        let result = proxy.read_resource(&ctx, "test://r").expect("read ok");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, Some("resource".to_string()));
    }

    #[test]
    fn proxy_client_get_prompt() {
        let state = Arc::new(Mutex::new(TestState::default()));
        let backend = TestBackend {
            state: Arc::clone(&state),
            ..TestBackend::default()
        };
        let proxy = ProxyClient::from_backend(backend);
        let ctx = McpContext::new(Cx::for_testing(), 1);
        let mut args = HashMap::new();
        args.insert("k".to_string(), "v".to_string());
        let result = proxy
            .get_prompt(&ctx, "test-prompt", args.clone())
            .expect("get ok");
        assert_eq!(result.len(), 1);

        let guard = state.lock().unwrap();
        let (name, recorded) = guard.last_prompt.as_ref().unwrap();
        assert_eq!(name, "test-prompt");
        assert_eq!(recorded, &args);
    }

    #[test]
    fn proxy_client_call_tool() {
        let state = Arc::new(Mutex::new(TestState::default()));
        let backend = TestBackend {
            state: Arc::clone(&state),
            ..TestBackend::default()
        };
        let proxy = ProxyClient::from_backend(backend);
        let ctx = McpContext::new(Cx::for_testing(), 1);
        let args = serde_json::json!({"x": 42});
        let result = proxy
            .call_tool(&ctx, "my-tool", args.clone())
            .expect("call ok");
        assert_eq!(result.len(), 1);

        let guard = state.lock().unwrap();
        let (name, recorded) = guard.last_tool.as_ref().unwrap();
        assert_eq!(name, "my-tool");
        assert_eq!(recorded, &args);
    }

    // =========================================================================
    // ProxyResourceHandler new/with_prefix stores external_uri
    // =========================================================================

    #[test]
    fn proxy_resource_handler_new_stores_external_uri() {
        use super::ProxyResourceHandler;

        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyResourceHandler::new(
            Resource {
                uri: "original://uri".to_string(),
                name: "Orig".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            },
            proxy,
        );
        assert_eq!(handler.external_uri, "original://uri");
    }

    #[test]
    fn proxy_resource_handler_with_prefix_stores_external_uri() {
        use super::ProxyResourceHandler;

        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyResourceHandler::with_prefix(
            Resource {
                uri: "original://uri".to_string(),
                name: "Orig".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            },
            "pfx",
            proxy,
        );
        // External URI is the original, not the prefixed one
        assert_eq!(handler.external_uri, "original://uri");
        // But the resource URI is prefixed
        assert_eq!(handler.resource.uri, "pfx/original://uri");
    }

    // =========================================================================
    // ProxyToolHandler stores external_name
    // =========================================================================

    #[test]
    fn proxy_tool_handler_new_stores_external_name() {
        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyToolHandler::new(
            Tool {
                name: "orig-name".to_string(),
                description: None,
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            },
            proxy,
        );
        assert_eq!(handler.external_name, "orig-name");
        assert_eq!(handler.tool.name, "orig-name");
    }

    #[test]
    fn proxy_tool_handler_with_prefix_stores_external_name() {
        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyToolHandler::with_prefix(
            Tool {
                name: "orig".to_string(),
                description: None,
                input_schema: serde_json::json!({}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            },
            "ns",
            proxy,
        );
        assert_eq!(handler.external_name, "orig");
        assert_eq!(handler.tool.name, "ns/orig");
    }

    // =========================================================================
    // ProxyPromptHandler stores external_name
    // =========================================================================

    #[test]
    fn proxy_prompt_handler_new_stores_external_name() {
        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyPromptHandler::new(
            Prompt {
                name: "orig-prompt".to_string(),
                description: None,
                arguments: Vec::new(),
                icon: None,
                version: None,
                tags: vec![],
            },
            proxy,
        );
        assert_eq!(handler.external_name, "orig-prompt");
    }

    #[test]
    fn proxy_prompt_handler_with_prefix_stores_external_name() {
        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyPromptHandler::with_prefix(
            Prompt {
                name: "prompt1".to_string(),
                description: None,
                arguments: Vec::new(),
                icon: None,
                version: None,
                tags: vec![],
            },
            "scope",
            proxy,
        );
        assert_eq!(handler.external_name, "prompt1");
        assert_eq!(handler.prompt.name, "scope/prompt1");
    }

    // =========================================================================
    // resource_from_template with minimal fields
    // =========================================================================

    #[test]
    fn resource_from_template_minimal_fields() {
        use fastmcp_protocol::ResourceTemplate;

        let template = ResourceTemplate {
            uri_template: "test://{id}".to_string(),
            name: "Minimal".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let resource = super::resource_from_template(&template);
        assert_eq!(resource.uri, "test://{id}");
        assert_eq!(resource.name, "Minimal");
        assert!(resource.description.is_none());
        assert!(resource.mime_type.is_none());
        assert!(resource.icon.is_none());
        assert!(resource.version.is_none());
        assert!(resource.tags.is_empty());
    }

    // =========================================================================
    // Error propagation for resource read and prompt get
    // =========================================================================

    #[test]
    fn proxy_client_read_resource_propagates_error() {
        let proxy = ProxyClient::from_backend(FailingBackend);
        let ctx = McpContext::new(Cx::for_testing(), 1);
        let result = proxy.read_resource(&ctx, "test://x");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("resource read failed"));
    }

    #[test]
    fn proxy_client_get_prompt_propagates_error() {
        let proxy = ProxyClient::from_backend(FailingBackend);
        let ctx = McpContext::new(Cx::for_testing(), 1);
        let result = proxy.get_prompt(&ctx, "fail", HashMap::new());
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("prompt get failed"));
    }

    #[test]
    fn proxy_client_call_tool_propagates_error() {
        let proxy = ProxyClient::from_backend(FailingBackend);
        let ctx = McpContext::new(Cx::for_testing(), 1);
        let result = proxy.call_tool(&ctx, "fail", serde_json::json!({}));
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("tool call failed"));
    }

    // =========================================================================
    // ProxyClient — lock poison error
    // =========================================================================

    #[test]
    fn proxy_client_lock_poison_returns_error() {
        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);

        // Poison the mutex by panicking inside a lock
        let proxy2 = proxy.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = proxy2.inner.lock().unwrap();
            panic!("intentional poison");
        }));

        // Now the lock is poisoned — catalog should return an error
        let result = proxy.catalog();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .message
                .contains("Proxy backend lock poisoned")
        );
    }

    // =========================================================================
    // ProxyResourceHandler — from_template stores external_uri
    // =========================================================================

    #[test]
    fn proxy_resource_handler_from_template_stores_external_uri() {
        use super::ProxyResourceHandler;
        use fastmcp_protocol::ResourceTemplate;

        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let template = ResourceTemplate {
            uri_template: "file://{path}".to_string(),
            name: "File".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let handler = ProxyResourceHandler::from_template(template, proxy);
        assert_eq!(handler.external_uri, "file://{path}");
    }

    #[test]
    fn proxy_resource_handler_from_template_with_prefix_stores_external_uri() {
        use super::ProxyResourceHandler;
        use fastmcp_protocol::ResourceTemplate;

        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let template = ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "DB".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let handler = ProxyResourceHandler::from_template_with_prefix(template, "remote", proxy);
        // External URI is the original template URI
        assert_eq!(handler.external_uri, "db://{table}");
        // Resource URI is prefixed
        assert_eq!(handler.resource.uri, "remote/db://{table}");
        // Template is also prefixed
        let tmpl = handler.template.unwrap();
        assert_eq!(tmpl.uri_template, "remote/db://{table}");
    }

    // =========================================================================
    // ProxyClient — call_tool with progress reporter
    // =========================================================================

    struct TestNotificationSender {
        calls: Mutex<Vec<(f64, Option<f64>, Option<String>)>>,
    }

    impl fastmcp_core::NotificationSender for TestNotificationSender {
        fn send_progress(&self, progress: f64, total: Option<f64>, message: Option<&str>) {
            self.calls
                .lock()
                .unwrap()
                .push((progress, total, message.map(|s| s.to_string())));
        }
    }

    #[test]
    fn proxy_client_call_tool_with_progress_reporter() {
        use fastmcp_core::ProgressReporter;

        let state = Arc::new(Mutex::new(TestState::default()));
        let backend = TestBackend {
            state: Arc::clone(&state),
            ..TestBackend::default()
        };
        let proxy = ProxyClient::from_backend(backend);

        let sender = Arc::new(TestNotificationSender {
            calls: Mutex::new(Vec::new()),
        });
        let reporter =
            ProgressReporter::new(Arc::clone(&sender) as Arc<dyn fastmcp_core::NotificationSender>);
        let ctx = McpContext::with_progress(Cx::for_testing(), 1, reporter);

        let result = proxy
            .call_tool(&ctx, "progress-tool", serde_json::json!({"x": 1}))
            .expect("call ok");
        assert_eq!(result.len(), 1);

        // The TestBackend's call_tool_with_progress calls on_progress(0.5, Some(1.0), ...)
        // which triggers ctx.report_progress_with_total
        let calls = sender.calls.lock().unwrap();
        assert!(!calls.is_empty());
        assert!((calls[0].0 - 0.5).abs() < f64::EPSILON);
        assert!(calls[0].1.is_some_and(|v| (v - 1.0).abs() < f64::EPSILON));
    }

    // =========================================================================
    // read_with_uri — URI without slash in resource URI
    // =========================================================================

    #[test]
    fn proxy_resource_handler_read_with_uri_resource_uri_no_slash() {
        use super::ProxyResourceHandler;
        use crate::handler::ResourceHandler;

        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        // Resource URI without any slash — split('/').next() returns the whole string
        let handler = ProxyResourceHandler::new(
            Resource {
                uri: "noslash".to_string(),
                name: "NoSlash".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            },
            proxy,
        );

        let ctx = McpContext::new(Cx::for_testing(), 1);
        let params = HashMap::new();
        // URI that starts with "noslash/" — prefix will match
        let result = handler
            .read_with_uri(&ctx, "noslash/rest", &params)
            .expect("read ok");
        assert_eq!(result.len(), 1);
    }

    // =========================================================================
    // ProxyCatalog — resource_templates populated
    // =========================================================================

    #[test]
    fn proxy_catalog_collects_resource_templates() {
        use fastmcp_protocol::ResourceTemplate;

        struct TemplateBackend;
        impl ProxyBackend for TemplateBackend {
            fn list_tools(&mut self) -> fastmcp_core::McpResult<Vec<Tool>> {
                Ok(vec![])
            }
            fn list_resources(&mut self) -> fastmcp_core::McpResult<Vec<Resource>> {
                Ok(vec![])
            }
            fn list_resource_templates(
                &mut self,
            ) -> fastmcp_core::McpResult<Vec<ResourceTemplate>> {
                Ok(vec![ResourceTemplate {
                    uri_template: "tmpl://{id}".to_string(),
                    name: "Template".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                }])
            }
            fn list_prompts(&mut self) -> fastmcp_core::McpResult<Vec<Prompt>> {
                Ok(vec![])
            }
            fn call_tool(
                &mut self,
                _: &str,
                _: serde_json::Value,
            ) -> fastmcp_core::McpResult<Vec<Content>> {
                Ok(vec![])
            }
            fn call_tool_with_progress(
                &mut self,
                _: &str,
                _: serde_json::Value,
                _: super::ProgressCallback<'_>,
            ) -> fastmcp_core::McpResult<Vec<Content>> {
                Ok(vec![])
            }
            fn read_resource(&mut self, _: &str) -> fastmcp_core::McpResult<Vec<ResourceContent>> {
                Ok(vec![])
            }
            fn get_prompt(
                &mut self,
                _: &str,
                _: HashMap<String, String>,
            ) -> fastmcp_core::McpResult<Vec<PromptMessage>> {
                Ok(vec![])
            }
        }

        let mut backend = TemplateBackend;
        let catalog = ProxyCatalog::from_backend(&mut backend).expect("catalog");
        assert_eq!(catalog.resource_templates.len(), 1);
        assert_eq!(catalog.resource_templates[0].uri_template, "tmpl://{id}");
    }

    // =========================================================================
    // FailingBackend — catalog errors propagate from resource list
    // =========================================================================

    #[test]
    fn proxy_catalog_propagates_resource_list_error() {
        // FailingBackend.list_tools fails first, but let's verify the error message
        let mut backend = FailingBackend;
        let result = ProxyCatalog::from_backend(&mut backend);
        assert!(result.is_err());
        // The first error encountered is from list_tools
        assert!(result.unwrap_err().message.contains("tool list failed"));
    }

    // =========================================================================
    // ProxyClient — call_tool without progress (no_progress path)
    // =========================================================================

    #[test]
    fn proxy_client_call_tool_no_progress_uses_plain_call() {
        let state = Arc::new(Mutex::new(TestState::default()));
        let backend = TestBackend {
            state: Arc::clone(&state),
            ..TestBackend::default()
        };
        let proxy = ProxyClient::from_backend(backend);

        // McpContext::new has no progress reporter
        let ctx = McpContext::new(Cx::for_testing(), 1);
        assert!(!ctx.has_progress_reporter());

        let result = proxy
            .call_tool(&ctx, "plain-tool", serde_json::json!({"y": 2}))
            .expect("call ok");
        assert_eq!(result.len(), 1);

        let guard = state.lock().unwrap();
        let (name, _) = guard.last_tool.as_ref().unwrap();
        assert_eq!(name, "plain-tool");
    }

    // =========================================================================
    // resource_from_template — icon field
    // =========================================================================

    #[test]
    fn resource_from_template_copies_icon() {
        use fastmcp_protocol::{Icon, ResourceTemplate};

        let icon = Icon {
            src: Some("https://example.com/star.png".to_string()),
            mime_type: None,
            sizes: None,
        };
        let template = ResourceTemplate {
            uri_template: "icon://{x}".to_string(),
            name: "WithIcon".to_string(),
            description: None,
            mime_type: None,
            icon: Some(icon.clone()),
            version: None,
            tags: vec![],
        };
        let resource = super::resource_from_template(&template);
        assert_eq!(resource.icon, Some(icon));
    }

    // =========================================================================
    // Progress callback — None total branch
    // =========================================================================

    /// Backend that invokes the progress callback with `None` total,
    /// exercising the `report_progress` (no total) path in `ProxyClient::call_tool`.
    struct NoTotalProgressBackend {
        state: Arc<Mutex<TestState>>,
    }

    impl ProxyBackend for NoTotalProgressBackend {
        fn list_tools(&mut self) -> fastmcp_core::McpResult<Vec<Tool>> {
            Ok(vec![])
        }
        fn list_resources(&mut self) -> fastmcp_core::McpResult<Vec<Resource>> {
            Ok(vec![])
        }
        fn list_resource_templates(
            &mut self,
        ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceTemplate>> {
            Ok(vec![])
        }
        fn list_prompts(&mut self) -> fastmcp_core::McpResult<Vec<Prompt>> {
            Ok(vec![])
        }
        fn call_tool(
            &mut self,
            name: &str,
            arguments: serde_json::Value,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            let mut guard = self.state.lock().expect("state lock poisoned");
            guard.last_tool.replace((name.to_string(), arguments));
            Ok(vec![Content::Text {
                text: "ok".to_string(),
            }])
        }
        fn call_tool_with_progress(
            &mut self,
            name: &str,
            arguments: serde_json::Value,
            on_progress: super::ProgressCallback<'_>,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            // Call with None total to exercise the else branch
            on_progress(0.3, None, Some("partial".to_string()));
            self.call_tool(name, arguments)
        }
        fn read_resource(&mut self, _uri: &str) -> fastmcp_core::McpResult<Vec<ResourceContent>> {
            Ok(vec![])
        }
        fn get_prompt(
            &mut self,
            _name: &str,
            _arguments: HashMap<String, String>,
        ) -> fastmcp_core::McpResult<Vec<PromptMessage>> {
            Ok(vec![])
        }
    }

    #[test]
    fn proxy_client_call_tool_with_progress_none_total() {
        use fastmcp_core::ProgressReporter;

        let state = Arc::new(Mutex::new(TestState::default()));
        let backend = NoTotalProgressBackend {
            state: Arc::clone(&state),
        };
        let proxy = ProxyClient::from_backend(backend);

        let sender = Arc::new(TestNotificationSender {
            calls: Mutex::new(Vec::new()),
        });
        let reporter =
            ProgressReporter::new(Arc::clone(&sender) as Arc<dyn fastmcp_core::NotificationSender>);
        let ctx = McpContext::with_progress(Cx::for_testing(), 1, reporter);

        let result = proxy
            .call_tool(&ctx, "no-total", serde_json::json!({}))
            .expect("call ok");
        assert_eq!(result.len(), 1);

        let calls = sender.calls.lock().unwrap();
        assert!(!calls.is_empty());
        // Total should be None since the backend passes None
        assert!(calls[0].1.is_none());
    }

    // =========================================================================
    // Partial catalog failures — list_resources, list_templates, list_prompts
    // =========================================================================

    /// A backend where list_tools succeeds but list_resources fails.
    struct FailAtResourcesBackend;

    impl ProxyBackend for FailAtResourcesBackend {
        fn list_tools(&mut self) -> fastmcp_core::McpResult<Vec<Tool>> {
            Ok(vec![])
        }
        fn list_resources(&mut self) -> fastmcp_core::McpResult<Vec<Resource>> {
            Err(fastmcp_core::McpError::internal_error(
                "resource list failed",
            ))
        }
        fn list_resource_templates(
            &mut self,
        ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceTemplate>> {
            Ok(vec![])
        }
        fn list_prompts(&mut self) -> fastmcp_core::McpResult<Vec<Prompt>> {
            Ok(vec![])
        }
        fn call_tool(
            &mut self,
            _: &str,
            _: serde_json::Value,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Ok(vec![])
        }
        fn call_tool_with_progress(
            &mut self,
            _: &str,
            _: serde_json::Value,
            _: super::ProgressCallback<'_>,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Ok(vec![])
        }
        fn read_resource(&mut self, _: &str) -> fastmcp_core::McpResult<Vec<ResourceContent>> {
            Ok(vec![])
        }
        fn get_prompt(
            &mut self,
            _: &str,
            _: HashMap<String, String>,
        ) -> fastmcp_core::McpResult<Vec<PromptMessage>> {
            Ok(vec![])
        }
    }

    #[test]
    fn proxy_catalog_propagates_resource_list_error_directly() {
        let mut backend = FailAtResourcesBackend;
        let result = ProxyCatalog::from_backend(&mut backend);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("resource list failed"));
    }

    /// A backend where list_tools and list_resources succeed but list_resource_templates fails.
    struct FailAtTemplatesBackend;

    impl ProxyBackend for FailAtTemplatesBackend {
        fn list_tools(&mut self) -> fastmcp_core::McpResult<Vec<Tool>> {
            Ok(vec![])
        }
        fn list_resources(&mut self) -> fastmcp_core::McpResult<Vec<Resource>> {
            Ok(vec![])
        }
        fn list_resource_templates(
            &mut self,
        ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceTemplate>> {
            Err(fastmcp_core::McpError::internal_error(
                "template list failed",
            ))
        }
        fn list_prompts(&mut self) -> fastmcp_core::McpResult<Vec<Prompt>> {
            Ok(vec![])
        }
        fn call_tool(
            &mut self,
            _: &str,
            _: serde_json::Value,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Ok(vec![])
        }
        fn call_tool_with_progress(
            &mut self,
            _: &str,
            _: serde_json::Value,
            _: super::ProgressCallback<'_>,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Ok(vec![])
        }
        fn read_resource(&mut self, _: &str) -> fastmcp_core::McpResult<Vec<ResourceContent>> {
            Ok(vec![])
        }
        fn get_prompt(
            &mut self,
            _: &str,
            _: HashMap<String, String>,
        ) -> fastmcp_core::McpResult<Vec<PromptMessage>> {
            Ok(vec![])
        }
    }

    #[test]
    fn proxy_catalog_propagates_template_list_error() {
        let mut backend = FailAtTemplatesBackend;
        let result = ProxyCatalog::from_backend(&mut backend);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("template list failed"));
    }

    /// A backend where everything succeeds except list_prompts.
    struct FailAtPromptsBackend;

    impl ProxyBackend for FailAtPromptsBackend {
        fn list_tools(&mut self) -> fastmcp_core::McpResult<Vec<Tool>> {
            Ok(vec![])
        }
        fn list_resources(&mut self) -> fastmcp_core::McpResult<Vec<Resource>> {
            Ok(vec![])
        }
        fn list_resource_templates(
            &mut self,
        ) -> fastmcp_core::McpResult<Vec<fastmcp_protocol::ResourceTemplate>> {
            Ok(vec![])
        }
        fn list_prompts(&mut self) -> fastmcp_core::McpResult<Vec<Prompt>> {
            Err(fastmcp_core::McpError::internal_error("prompt list failed"))
        }
        fn call_tool(
            &mut self,
            _: &str,
            _: serde_json::Value,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Ok(vec![])
        }
        fn call_tool_with_progress(
            &mut self,
            _: &str,
            _: serde_json::Value,
            _: super::ProgressCallback<'_>,
        ) -> fastmcp_core::McpResult<Vec<Content>> {
            Ok(vec![])
        }
        fn read_resource(&mut self, _: &str) -> fastmcp_core::McpResult<Vec<ResourceContent>> {
            Ok(vec![])
        }
        fn get_prompt(
            &mut self,
            _: &str,
            _: HashMap<String, String>,
        ) -> fastmcp_core::McpResult<Vec<PromptMessage>> {
            Ok(vec![])
        }
    }

    #[test]
    fn proxy_catalog_propagates_prompt_list_error() {
        let mut backend = FailAtPromptsBackend;
        let result = ProxyCatalog::from_backend(&mut backend);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("prompt list failed"));
    }

    // =========================================================================
    // read_with_uri on template-based handlers
    // =========================================================================

    #[test]
    fn proxy_resource_handler_from_template_read_with_uri() {
        use super::ProxyResourceHandler;
        use crate::handler::ResourceHandler;
        use fastmcp_protocol::ResourceTemplate;

        let backend = TestBackend::default();
        let state = Arc::clone(&backend.state);
        let proxy = ProxyClient::from_backend(backend);
        let template = ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "DB".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let handler = ProxyResourceHandler::from_template(template, proxy);

        let ctx = McpContext::new(Cx::for_testing(), 1);
        let mut params = HashMap::new();
        params.insert("table".to_string(), "users".to_string());
        let result = handler
            .read_with_uri(&ctx, "db://users", &params)
            .expect("read ok");
        assert_eq!(result.len(), 1);
        assert_eq!(
            state.lock().expect("state lock poisoned").last_resource,
            Some("db://users".to_string())
        );
    }

    #[test]
    fn proxy_resource_handler_from_template_with_prefix_read_with_uri() {
        use super::ProxyResourceHandler;
        use crate::handler::ResourceHandler;
        use fastmcp_protocol::ResourceTemplate;

        let backend = TestBackend::default();
        let state = Arc::clone(&backend.state);
        let proxy = ProxyClient::from_backend(backend);
        let template = ResourceTemplate {
            uri_template: "db://{table}".to_string(),
            name: "DB".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let handler =
            ProxyResourceHandler::from_template_with_prefix(template, "tenant/remote", proxy);

        let ctx = McpContext::new(Cx::for_testing(), 1);
        let mut params = HashMap::new();
        params.insert("table".to_string(), "orders".to_string());
        // Prefixed URI
        let result = handler
            .read_with_uri(&ctx, "tenant/remote/db://orders", &params)
            .expect("read ok");
        assert_eq!(result.len(), 1);
        assert_eq!(
            state.lock().expect("state lock poisoned").last_resource,
            Some("db://orders".to_string())
        );
    }

    // =========================================================================
    // Prompt definition preserves arguments
    // =========================================================================

    #[test]
    fn proxy_prompt_handler_definition_preserves_arguments() {
        use fastmcp_protocol::PromptArgument;

        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyPromptHandler::new(
            Prompt {
                name: "templated".to_string(),
                description: Some("prompt with args".to_string()),
                arguments: vec![
                    PromptArgument {
                        name: "name".to_string(),
                        description: Some("User name".to_string()),
                        required: true,
                    },
                    PromptArgument {
                        name: "lang".to_string(),
                        description: None,
                        required: false,
                    },
                ],
                icon: None,
                version: None,
                tags: vec![],
            },
            proxy,
        );

        let def = handler.definition();
        assert_eq!(def.arguments.len(), 2);
        assert_eq!(def.arguments[0].name, "name");
        assert!(def.arguments[0].required);
        assert_eq!(def.arguments[1].name, "lang");
        assert!(!def.arguments[1].required);
    }

    // =========================================================================
    // Prefixed prompt definition preserves arguments
    // =========================================================================

    #[test]
    fn prefixed_prompt_handler_definition_preserves_arguments() {
        use fastmcp_protocol::PromptArgument;

        let backend = TestBackend::default();
        let proxy = ProxyClient::from_backend(backend);
        let handler = ProxyPromptHandler::with_prefix(
            Prompt {
                name: "greet".to_string(),
                description: None,
                arguments: vec![PromptArgument {
                    name: "user".to_string(),
                    description: None,
                    required: true,
                }],
                icon: None,
                version: None,
                tags: vec![],
            },
            "ns",
            proxy,
        );

        let def = handler.definition();
        assert_eq!(def.name, "ns/greet");
        assert_eq!(def.arguments.len(), 1);
        assert_eq!(def.arguments[0].name, "user");
    }
}
