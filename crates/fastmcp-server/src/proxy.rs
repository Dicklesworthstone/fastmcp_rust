//! Proxy/composition support for MCP servers.
//!
//! This module provides lightweight proxy handlers that forward tool/resource/prompt
//! calls to another MCP server via a backend client.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use fastmcp_client::{Client, ClientProtocolPlan};
use fastmcp_core::{CanonicalHttpUrl, McpContext, McpError, McpResult};
use fastmcp_protocol::methods::translate_legacy_2024_result;
use fastmcp_protocol::protocol_policy::{
    HttpEndpointBundle, HttpEndpointBundleKey, HttpEraCache, HttpEraDecision, HttpModernProbe,
    ModernVersionSupport, ProtocolEra, ProtocolPolicy, ProtocolVersion, StdioEraClassifier,
    StdioEraDecision, StdioOpeningFrame,
};
use fastmcp_protocol::{
    Content, Prompt, PromptMessage, Resource, ResourceContent, ResourceTemplate, Tool,
};

use crate::handler::{PromptHandler, ResourceHandler, ToolHandler, UriParams};

/// Progress callback signature used by proxy backends.
pub type ProgressCallback<'a> = &'a mut dyn FnMut(f64, Option<f64>, Option<String>);

/// Backend interface used by proxy handlers.
pub trait ProxyBackend: Send {
    /// Lists available tools.
    fn list_tools(&mut self) -> McpResult<Vec<Tool>>;
    /// Lists available resources.
    fn list_resources(&mut self) -> McpResult<Vec<Resource>>;
    /// Lists available resource templates.
    fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>>;
    /// Lists available prompts.
    fn list_prompts(&mut self) -> McpResult<Vec<Prompt>>;
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
}

impl ProxyBackend for Client {
    fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
        self.ensure_initialized()?;
        if self.server_capabilities().tools.is_none() {
            return Ok(Vec::new());
        }
        Client::list_tools(self)
    }

    fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        self.ensure_initialized()?;
        if self.server_capabilities().resources.is_none() {
            return Ok(Vec::new());
        }
        Client::list_resources(self)
    }

    fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
        self.ensure_initialized()?;
        if self.server_capabilities().resources.is_none() {
            return Ok(Vec::new());
        }
        Client::list_resource_templates(self)
    }

    fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
        self.ensure_initialized()?;
        if self.server_capabilities().prompts.is_none() {
            return Ok(Vec::new());
        }
        Client::list_prompts(self)
    }

    fn call_tool(&mut self, name: &str, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Client::call_tool(self, name, arguments)
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
        Client::call_tool_with_progress(self, name, arguments, &mut wrapper)
    }

    fn read_resource(&mut self, uri: &str) -> McpResult<Vec<ResourceContent>> {
        Client::read_resource(self, uri)
    }

    fn get_prompt(
        &mut self,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        Client::get_prompt(self, name, arguments)
    }
}

/// Catalog of remote definitions used to register proxy handlers.
#[derive(Debug, Clone, Default)]
pub struct ProxyCatalog {
    /// Remote tool definitions.
    pub tools: Vec<Tool>,
    /// Remote resource definitions.
    pub resources: Vec<Resource>,
    /// Remote resource templates.
    pub resource_templates: Vec<ResourceTemplate>,
    /// Remote prompt definitions.
    pub prompts: Vec<Prompt>,
}

impl ProxyCatalog {
    /// Builds a catalog by querying a proxy backend.
    pub fn from_backend<B: ProxyBackend + ?Sized>(backend: &mut B) -> McpResult<Self> {
        Ok(Self {
            tools: backend.list_tools()?,
            resources: backend.list_resources()?,
            resource_templates: backend.list_resource_templates()?,
            prompts: backend.list_prompts()?,
        })
    }

    /// Builds a catalog by querying a client.
    pub fn from_client(client: &mut Client) -> McpResult<Self> {
        Self::from_backend(client)
    }
}

/// Shared proxy client wrapper for handler reuse.
#[derive(Clone)]
pub struct ProxyClient {
    inner: Arc<Mutex<dyn ProxyBackend>>,
    upstream_binding: Option<ProxyUpstreamBinding>,
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

/// Cache of immutable selections for independently configured proxy upstreams.
///
/// A cache entry is never keyed by an origin alone. Route, complete transport
/// identity, policy (inside the HTTP bundle), adapter receipt identity, and
/// configuration generation all participate in its identity.
#[derive(Debug, Default)]
pub struct ProxyUpstreamBindingRegistry {
    stdio: HashMap<StdioBindingKey, ProxyUpstreamBinding>,
    live_stdio: HashMap<LiveStdioBindingKey, ProxyUpstreamBinding>,
    http: HashMap<HttpBindingKey, ProxyUpstreamBinding>,
    http_eras: HttpEraCache,
}

impl ProxyUpstreamBindingRegistry {
    /// Opens a real stdio upstream from an immutable client protocol plan.
    ///
    /// The binding is derived from the connected client's selected era, never
    /// from caller-provided opening-frame assumptions. `Auto` therefore uses
    /// the client's modern-first discovery and only observes the client's
    /// narrowly authorized fallback behavior. A cache entry is inserted only
    /// after both connection and exact selected-era admission succeed.
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
        let mut client =
            Client::stdio_with_protocol_plan_with_cx(command, args, protocol_plan, cx)?;
        let binding = binding_from_live_stdio_client(&client, configuration_generation)?;

        if let Some(existing) = self.live_stdio.get(&key)
            && *existing != binding
        {
            let mismatch = McpError::invalid_request(
                "A live upstream selected an era that conflicts with its successful cached binding",
            );
            return match client.close() {
                Ok(()) => Err(mismatch),
                Err(cleanup_error) => Err(McpError::internal_error(format!(
                    "{mismatch}; additionally failed to close the conflicting upstream: {cleanup_error}"
                ))),
            };
        }

        let upstream_protocol_version = client.protocol_version().to_owned();
        let proxy = ProxyClient::from_backend_with_upstream_binding(
            client,
            binding,
            &upstream_protocol_version,
        )?;
        self.live_stdio.insert(key, binding);
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
        self.with_backend(|backend| ProxyCatalog::from_backend(backend))
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
        let content = self.with_backend(|backend| {
            if ctx.has_progress_reporter() {
                let mut callback = |progress, total, message: Option<String>| {
                    if let Some(total) = total {
                        ctx.report_progress_with_total(progress, total, message.as_deref());
                    } else {
                        ctx.report_progress(progress, message.as_deref());
                    }
                };
                backend.call_tool_with_progress(name, arguments, &mut callback)
            } else {
                backend.call_tool(name, arguments)
            }
        })?;
        self.translate_upstream_response("tools/call", "content", content)
    }

    pub fn read_resource(&self, ctx: &McpContext, uri: &str) -> McpResult<Vec<ResourceContent>> {
        ctx.checkpoint()?;
        let contents = self.with_backend(|backend| backend.read_resource(uri))?;
        self.translate_upstream_response("resources/read", "contents", contents)
    }

    pub fn get_prompt(
        &self,
        ctx: &McpContext,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        ctx.checkpoint()?;
        let messages = self.with_backend(|backend| backend.get_prompt(name, arguments))?;
        self.translate_upstream_response("prompts/get", "messages", messages)
    }

    fn translate_upstream_response<T>(
        &self,
        method: &str,
        member: &str,
        response: T,
    ) -> McpResult<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let Some(binding) = self.upstream_binding else {
            return Ok(response);
        };
        if binding.era() == ProtocolEra::Modern2026 {
            return Ok(response);
        }

        let mut envelope = serde_json::Map::new();
        envelope.insert(
            member.to_owned(),
            serde_json::to_value(response).map_err(|_| {
                McpError::invalid_params("Upstream result could not be represented for translation")
            })?,
        );
        let translated =
            binding.translate_upstream_result(method, serde_json::Value::Object(envelope))?;
        let response = translated.get(member).cloned().ok_or_else(|| {
            McpError::invalid_params(
                "Lossless upstream translation omitted its required result member",
            )
        })?;
        serde_json::from_value(response).map_err(|_| {
            McpError::invalid_params(
                "Lossless upstream translation produced an invalid result member",
            )
        })
    }
}

pub(crate) struct ProxyToolHandler {
    /// The tool definition as exposed to clients (may have prefixed name).
    tool: Tool,
    /// The original tool name on the remote server (for forwarding).
    external_name: String,
    client: ProxyClient,
}

impl ProxyToolHandler {
    pub(crate) fn new(tool: Tool, client: ProxyClient) -> Self {
        let external_name = tool.name.clone();
        Self {
            tool,
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
            external_name,
            client,
        }
    }
}

impl ToolHandler for ProxyToolHandler {
    fn definition(&self) -> Tool {
        self.tool.clone()
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        // Forward using the original external name
        self.client.call_tool(ctx, &self.external_name, arguments)
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
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    #[cfg(unix)]
    use std::time::Duration;

    use asupersync::Cx;
    #[cfg(unix)]
    use fastmcp_client::RequestTimeoutPolicy;
    use fastmcp_core::McpContext;
    use fastmcp_protocol::{Content, Prompt, PromptMessage, Resource, ResourceContent, Tool};

    use super::{ProxyBackend, ProxyCatalog, ProxyClient, ProxyPromptHandler, ProxyToolHandler};
    use crate::handler::{PromptHandler, ToolHandler};

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
                    code: -32601,
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
                fastmcp_client::ClientProtocolPlan::stdio(
                    fastmcp_protocol::ProtocolPolicy::ModernOnly,
                ),
                Cx::for_testing(),
            )
            .expect("ModernOnly connects a live modern client");

        let binding = proxy.upstream_binding().expect("live binding is retained");
        assert_eq!(binding.era(), fastmcp_protocol::ProtocolEra::Modern2026);
        assert_eq!(binding.adapter(), super::ProxyUpstreamAdapter::ModernStdio);
        assert_eq!(
            binding.policy(),
            fastmcp_protocol::ProtocolPolicy::ModernOnly
        );
        assert_forwarded_tool(
            proxy
                .call_tool(
                    &McpContext::new(Cx::for_testing(), 100),
                    "echo",
                    serde_json::json!({}),
                )
                .expect("normal request uses the selected live client"),
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
                fastmcp_client::ClientProtocolPlan::stdio(fastmcp_protocol::ProtocolPolicy::Auto),
                Cx::for_testing(),
            )
            .expect("Auto retains its live modern selection");

        let binding = proxy.upstream_binding().expect("live binding is retained");
        assert_eq!(binding.era(), fastmcp_protocol::ProtocolEra::Modern2026);
        assert_eq!(binding.policy(), fastmcp_protocol::ProtocolPolicy::Auto);
        assert_forwarded_tool(
            proxy
                .call_tool(
                    &McpContext::new(Cx::for_testing(), 101),
                    "echo",
                    serde_json::json!({}),
                )
                .expect("Auto forwards ordinary requests through its live client"),
        );
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
                fastmcp_client::ClientProtocolPlan::stdio(fastmcp_protocol::ProtocolPolicy::Auto),
                Cx::for_testing(),
            )
            .expect("Auto selects exact legacy only after an authorized modern refusal");

        let binding = proxy.upstream_binding().expect("live binding is retained");
        assert_eq!(binding.era(), fastmcp_protocol::ProtocolEra::Legacy2024);
        assert_eq!(binding.adapter(), super::ProxyUpstreamAdapter::LegacyStdio);
        assert_eq!(binding.policy(), fastmcp_protocol::ProtocolPolicy::Auto);
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
                fastmcp_client::ClientProtocolPlan::stdio(
                    fastmcp_protocol::ProtocolPolicy::LegacyOnly,
                ),
                Cx::for_testing(),
            )
            .expect("LegacyOnly connects a live exact-2024 client");

        let binding = proxy.upstream_binding().expect("live binding is retained");
        assert_eq!(binding.era(), fastmcp_protocol::ProtocolEra::Legacy2024);
        assert_eq!(binding.adapter(), super::ProxyUpstreamAdapter::LegacyStdio);
        assert_eq!(
            binding.policy(),
            fastmcp_protocol::ProtocolPolicy::LegacyOnly
        );
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
    fn proxy_outbound_auto_malformed_modern_discovery_never_falls_back_to_legacy() {
        let malformed_discovery = modern_discovery_response_line(
            "auto-proxy-peer",
            &[fastmcp_protocol::PROTOCOL_VERSION],
        );
        let legacy_initialize = legacy_initialize_response_line();
        let script =
            malformed_modern_or_legacy_peer_script(&malformed_discovery, &legacy_initialize);
        let mut bindings = ProxyClient::upstream_binding_registry();

        let error = bindings
            .connect_stdio_with_protocol_plan(
                "auto-malformed-route",
                "stdio:auto-malformed-peer",
                5,
                "sh",
                &["-c", script.as_str()],
                fastmcp_client::ClientProtocolPlan::stdio(fastmcp_protocol::ProtocolPolicy::Auto),
                Cx::for_testing(),
            )
            .err()
            .expect("a malformed modern success must not start the available legacy peer");

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
