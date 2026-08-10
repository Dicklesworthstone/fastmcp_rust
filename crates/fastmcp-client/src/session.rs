//! Client session state.

use fastmcp_core::{CanonicalHttpUrl, McpError, McpResult};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;

use fastmcp_protocol::extensions::{
    ClientExtensionDiscovery, ExtensionDescriptor, ExtensionDescriptorRegistry, ExtensionDirection,
    ExtensionLocalEnablement, ExtensionNegotiationError, ExtensionSettings,
    ExtensionSettingsCompatibilityResolver, ExtensionSettingsResolution, McpAppsActivationReceipt,
    McpAppsClientSettings, McpAppsNegotiationResolver, NegotiatedExtensionSet,
    ServerExtensionDiscovery, official_mcp_apps_extension_id,
    official_mcp_apps_negotiation_resolver, register_official_mcp_apps_extension,
};
use fastmcp_protocol::protocol_policy::{
    HttpEndpointBundle, HttpEndpointBundleError, ProtocolEra, ProtocolPolicy, ProtocolVersion,
    ProtocolVersionError,
};
use fastmcp_protocol::{
    ClientCapabilities, ClientInfo, ServerCapabilities, ServerDiscoverResult, ServerInfo,
};

/// Sized bridge for a caller-provided dynamic client extension-settings resolver.
struct BoxedClientExtensionSettingsResolver(Box<dyn ExtensionSettingsCompatibilityResolver + Send>);

impl ExtensionSettingsCompatibilityResolver for BoxedClientExtensionSettingsResolver {
    fn resolve(
        &mut self,
        descriptor: &ExtensionDescriptor,
        client: &ExtensionSettings,
        server: &ExtensionSettings,
    ) -> Result<ExtensionSettings, ExtensionNegotiationError> {
        self.0.resolve(descriptor, client, server)
    }

    fn resolve_with_disposition(
        &mut self,
        descriptor: &ExtensionDescriptor,
        client: &ExtensionSettings,
        server: &ExtensionSettings,
    ) -> Result<ExtensionSettingsResolution, ExtensionNegotiationError> {
        self.0.resolve_with_disposition(descriptor, client, server)
    }
}

/// Builds one fresh settings resolver for each discovery exchange.
///
/// Extension settings resolvers are deliberately mutable: callers may use
/// them to retain per-negotiation validation state. The builder configuration,
/// however, is cloneable and may retry a connection. Keeping one resolver,
/// including a cloneable `Arc<Mutex<_>>`, would let a failed attempt influence
/// a retry or a cloned builder. This factory keeps the registry and discovery
/// settings immutable and invokes the caller's constructor for every
/// negotiation attempt.
trait ClientExtensionSettingsResolverFactory: Send + Sync {
    fn fresh_resolver(&self) -> BoxedClientExtensionSettingsResolver;
}

struct FreshClientExtensionSettingsResolverFactory<F, R> {
    factory: F,
    wraps_mcp_apps: bool,
    marker: PhantomData<fn() -> R>,
}

impl<F, R> ClientExtensionSettingsResolverFactory
    for FreshClientExtensionSettingsResolverFactory<F, R>
where
    F: Fn() -> R + Send + Sync + 'static,
    R: ExtensionSettingsCompatibilityResolver + Send + 'static,
{
    fn fresh_resolver(&self) -> BoxedClientExtensionSettingsResolver {
        let resolver = BoxedClientExtensionSettingsResolver(Box::new((self.factory)()));
        if self.wraps_mcp_apps {
            BoxedClientExtensionSettingsResolver(Box::new(
                McpAppsNegotiationResolver::with_fallback(resolver),
            ))
        } else {
            resolver
        }
    }
}

/// Immutable extension configuration frozen by [`crate::ClientBuilder`].
///
/// The descriptor receipt, local enablement, and client settings stay together
/// so a connection can negotiate once from `server/discover` and admit later
/// raw extension requests against that exact state.
#[derive(Clone)]
pub(crate) struct ClientExtensionRuntime {
    descriptors: ExtensionDescriptorRegistry,
    local_enablement: ExtensionLocalEnablement,
    client_discovery: ClientExtensionDiscovery,
    resolver_factory: Arc<dyn ClientExtensionSettingsResolverFactory>,
}

impl std::fmt::Debug for ClientExtensionRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientExtensionRuntime")
            .field("descriptor_count", &self.descriptors.descriptors().len())
            .field(
                "configured_extension_count",
                &self.client_discovery.extensions.len(),
            )
            .field("frozen", &self.descriptors.receipt().is_some())
            .finish_non_exhaustive()
    }
}

impl ClientExtensionRuntime {
    pub(crate) fn new<F, R>(
        mut descriptors: ExtensionDescriptorRegistry,
        client_discovery: ClientExtensionDiscovery,
        resolver_factory: F,
    ) -> McpResult<Self>
    where
        F: Fn() -> R + Send + Sync + 'static,
        R: ExtensionSettingsCompatibilityResolver + Send + 'static,
    {
        for extension_id in client_discovery.extensions.keys() {
            if descriptors.descriptor(extension_id).is_none() {
                return Err(McpError::invalid_params(format!(
                    "Client extension settings reference an unregistered descriptor: {extension_id}"
                )));
            }
        }
        descriptors.freeze().map_err(|error| {
            McpError::invalid_params(format!(
                "Client extension descriptor registry could not be frozen: {error}"
            ))
        })?;

        let mut local_enablement = ExtensionLocalEnablement::default();
        for extension_id in client_discovery.extensions.keys() {
            local_enablement.enable(extension_id.clone());
        }

        let wraps_mcp_apps = client_discovery
            .extensions
            .contains_key(&official_mcp_apps_extension_id());

        Ok(Self {
            descriptors,
            local_enablement,
            client_discovery,
            resolver_factory: Arc::new(FreshClientExtensionSettingsResolverFactory {
                factory: resolver_factory,
                wraps_mcp_apps,
                marker: PhantomData,
            }),
        })
    }

    pub(crate) fn client_wire_extensions(&self) -> BTreeMap<String, serde_json::Value> {
        self.client_discovery
            .extensions
            .iter()
            .map(|(id, settings)| (id.to_string(), settings.clone().into_value()))
            .collect()
    }

    pub(crate) fn negotiate(
        &self,
        discovery: &ServerDiscoverResult,
    ) -> McpResult<NegotiatedExtensionSet> {
        let capabilities = serde_json::to_value(discovery.capabilities()).map_err(|error| {
            McpError::internal_error(format!(
                "Final server/discover capabilities could not be retained for extension negotiation: {error}"
            ))
        })?;
        let extensions = capabilities
            .get("extensions")
            .and_then(serde_json::Value::as_object);
        let mut server = ServerExtensionDiscovery::default();
        if let Some(extensions) = extensions {
            for (name, settings) in extensions {
                let extension_id = fastmcp_protocol::ExtensionId::parse(name).map_err(|_| {
                    McpError::invalid_params(
                        "Final server/discover contains an invalid extension identifier",
                    )
                })?;
                let settings = ExtensionSettings::new(settings.clone()).map_err(|_| {
                    McpError::invalid_params(
                        "Final server/discover contains invalid extension settings",
                    )
                })?;
                server.extensions.insert(extension_id, settings);
            }
        }

        let mut resolver = self.resolver_factory.fresh_resolver();
        self.descriptors
            .negotiate(
                ProtocolEra::Modern2026,
                &self.local_enablement,
                &self.client_discovery,
                &server,
                &mut resolver,
            )
            .map_err(|error| {
                McpError::invalid_params(format!(
                    "Final client extension negotiation failed: {error}"
                ))
            })
    }

    pub(crate) fn admit_method(
        &self,
        negotiated: &NegotiatedExtensionSet,
        extension_id: &fastmcp_protocol::ExtensionId,
        method: &str,
    ) -> McpResult<()> {
        negotiated
            .admit_method(
                &self.descriptors,
                ProtocolEra::Modern2026,
                extension_id,
                method,
                ExtensionDirection::ClientToServer,
            )
            .map(|_| ())
            .map_err(|error| {
                McpError::invalid_params(format!(
                    "Final extension request is not admitted by the negotiated client capability: {error}"
                ))
            })
    }

    /// Returns whether a configured descriptor owns this raw request method.
    ///
    /// Public raw request surfaces use this to ensure a registered extension
    /// method cannot bypass final-era admission through a generic JSON-RPC
    /// method string.
    pub(crate) fn owns_method(&self, method: &str) -> bool {
        self.descriptors.descriptors().any(|descriptor| {
            self.descriptors
                .method_descriptor(&descriptor.id, method)
                .is_some()
        })
    }

    pub(crate) fn configures_mcp_apps(&self) -> bool {
        self.client_discovery
            .extensions
            .contains_key(&official_mcp_apps_extension_id())
    }

    pub(crate) fn configures_extension(&self, extension_id: &str) -> bool {
        self.client_discovery
            .extensions
            .keys()
            .any(|configured| configured.as_str() == extension_id)
    }

    pub(crate) fn mcp_apps_activation_receipt(
        &self,
        negotiated: &NegotiatedExtensionSet,
    ) -> Option<McpAppsActivationReceipt> {
        negotiated.mcp_apps_activation_receipt(&self.descriptors)
    }
}

/// Immutable transport policy and trusted endpoint configuration for one client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientProtocolPlan {
    policy: ProtocolPolicy,
    http_endpoints: Option<HttpEndpointBundle>,
    modern_post_target: Option<String>,
    legacy_sse_target: Option<String>,
    legacy_message_post_target: Option<String>,
}

impl ClientProtocolPlan {
    #[must_use]
    pub const fn stdio(policy: ProtocolPolicy) -> Self {
        Self {
            policy,
            http_endpoints: None,
            modern_post_target: None,
            legacy_sse_target: None,
            legacy_message_post_target: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn http(
        policy: ProtocolPolicy,
        modern_post: Option<CanonicalHttpUrl>,
        legacy_sse: Option<CanonicalHttpUrl>,
        legacy_message_post: Option<CanonicalHttpUrl>,
        credential_partition: String,
        security_partition: String,
        transport_profile: String,
        policy_generation: u64,
        configuration_generation: u64,
        legacy_receipt_generation: u64,
    ) -> Result<Self, HttpEndpointBundleError> {
        let modern_post_target = modern_post
            .as_ref()
            .map(|target| target.as_str().to_owned());
        let legacy_sse_target = legacy_sse.as_ref().map(|target| target.as_str().to_owned());
        let legacy_message_post_target = legacy_message_post
            .as_ref()
            .map(|target| target.as_str().to_owned());
        let http_endpoints = HttpEndpointBundle::new(
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
        )?;
        Ok(Self {
            policy,
            http_endpoints: Some(http_endpoints),
            modern_post_target,
            legacy_sse_target,
            legacy_message_post_target,
        })
    }

    #[must_use]
    pub const fn policy(&self) -> ProtocolPolicy {
        self.policy
    }

    #[must_use]
    pub const fn http_endpoints(&self) -> Option<&HttpEndpointBundle> {
        self.http_endpoints.as_ref()
    }

    /// Returns the exact configured canonical modern MCP POST target.
    ///
    /// The protocol bundle intentionally keeps route strings opaque for
    /// negotiation-cache identity. The native HTTP runtime still needs the
    /// configured target to issue its one disposable modern probe and the
    /// subsequent modern requests, so this accessor exposes only that route.
    #[must_use]
    pub fn modern_post_target(&self) -> Option<&str> {
        self.modern_post_target.as_deref()
    }

    /// Returns the exact configured canonical legacy SSE GET target.
    ///
    /// This value is copied from the validated endpoint input before the
    /// opaque bundle is built. The HTTP runtime uses it only to open the
    /// legacy event stream; it never derives a route from an observed event.
    #[must_use]
    pub fn legacy_sse_target(&self) -> Option<&str> {
        self.legacy_sse_target.as_deref()
    }

    /// Returns the exact configured canonical legacy message POST target.
    ///
    /// A legacy SSE endpoint advertisement must exactly match this immutable
    /// target before the runtime permits a JSON-RPC POST.
    #[must_use]
    pub fn legacy_message_post_target(&self) -> Option<&str> {
        self.legacy_message_post_target.as_deref()
    }
}

/// Rejection for a protocol plan that contradicts an already negotiated era.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProtocolPlanError {
    /// The plan's immutable policy forbids the era selected by the handshake.
    IncompatibleSelectedEra {
        /// The era selected by the completed handshake.
        selected_era: ProtocolEra,
        /// The policy that does not permit the selected era.
        policy: ProtocolPolicy,
    },
}

impl std::fmt::Display for ClientProtocolPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompatibleSelectedEra {
                selected_era,
                policy,
            } => write!(
                formatter,
                "protocol policy {policy:?} does not permit negotiated era {selected_era:?}"
            ),
        }
    }
}

impl std::error::Error for ClientProtocolPlanError {}

/// Client-side session state.
#[derive(Debug)]
pub struct ClientSession {
    /// Client info sent during initialization.
    client_info: ClientInfo,
    /// Client capabilities sent during initialization.
    client_capabilities: ClientCapabilities,
    /// Server info received during initialization.
    server_info: ServerInfo,
    /// Server capabilities received during initialization.
    server_capabilities: ServerCapabilities,
    /// Exact final discovery state when the modern handshake succeeded.
    ///
    /// Legacy initialization has no counterpart for final discovery
    /// capabilities, instructions, result metadata, or cache hints. Retaining
    /// the typed result keeps those final-only fields available without
    /// projecting them onto the legacy capability shape.
    server_discovery: Option<ServerDiscoverResult>,
    /// Local MCP Apps settings selected before connection.
    mcp_apps_settings: Option<McpAppsClientSettings>,
    /// Opaque bilateral Apps receipt retained from the current modern discovery
    /// exchange. Legacy and inactive sessions deliberately retain no receipt.
    mcp_apps_activation_receipt: Option<McpAppsActivationReceipt>,
    /// Immutable generic extension configuration installed by the builder.
    client_extension_runtime: Option<Arc<ClientExtensionRuntime>>,
    /// Frozen bilateral extension state retained from the successful final
    /// discovery exchange. Legacy sessions deliberately retain no set.
    negotiated_extensions: Option<NegotiatedExtensionSet>,
    /// Negotiated protocol version.
    protocol_version: String,
    /// Immutable era selected from the successful handshake.
    selected_era: Option<ProtocolEra>,
    /// Immutable policy and configured endpoint bundle for this client.
    protocol_plan: ClientProtocolPlan,
}

impl ClientSession {
    /// Creates a session only when the negotiated protocol version is supported.
    ///
    /// Callers completing a handshake must use this constructor so an
    /// unsupported wire spelling cannot create a session or select an era.
    pub fn try_new(
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        server_info: ServerInfo,
        server_capabilities: ServerCapabilities,
        protocol_version: String,
    ) -> Result<Self, ProtocolVersionError> {
        let selected_era = ProtocolVersion::parse(&protocol_version)?.era();
        Ok(Self::from_parts(
            client_info,
            client_capabilities,
            server_info,
            server_capabilities,
            protocol_version,
            Some(selected_era),
        ))
    }

    /// Creates the unselected placeholder state used before initialization.
    #[must_use]
    pub(crate) fn new_placeholder(
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        server_info: ServerInfo,
        server_capabilities: ServerCapabilities,
    ) -> Self {
        Self::from_parts(
            client_info,
            client_capabilities,
            server_info,
            server_capabilities,
            String::new(),
            None,
        )
    }

    fn from_parts(
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        server_info: ServerInfo,
        server_capabilities: ServerCapabilities,
        protocol_version: String,
        selected_era: Option<ProtocolEra>,
    ) -> Self {
        Self {
            client_info,
            client_capabilities,
            server_info,
            server_capabilities,
            server_discovery: None,
            mcp_apps_settings: None,
            mcp_apps_activation_receipt: None,
            client_extension_runtime: None,
            negotiated_extensions: None,
            selected_era,
            protocol_version,
            // A peer-selected era must never rewrite the pre-connect policy.
            protocol_plan: ClientProtocolPlan::stdio(ProtocolPolicy::Auto),
        }
    }

    /// Applies a plan only when it admits the already negotiated era.
    pub fn try_with_protocol_plan(
        mut self,
        protocol_plan: ClientProtocolPlan,
    ) -> Result<Self, ClientProtocolPlanError> {
        self.validate_protocol_plan(&protocol_plan)?;
        self.protocol_plan = protocol_plan;
        Ok(self)
    }

    /// Applies a plan that admits the already negotiated era.
    ///
    /// Prefer [`Self::try_with_protocol_plan`] when the plan comes from an
    /// external caller or configuration source.
    ///
    /// # Panics
    ///
    /// Panics when `protocol_plan` forbids the era selected by this session.
    #[must_use]
    pub fn with_protocol_plan(self, protocol_plan: ClientProtocolPlan) -> Self {
        self.try_with_protocol_plan(protocol_plan)
            .expect("protocol plan must admit the negotiated era")
    }

    pub(crate) fn with_server_discovery(mut self, server_discovery: ServerDiscoverResult) -> Self {
        self.server_discovery = Some(server_discovery);
        self
    }

    pub(crate) fn with_mcp_apps_settings(
        mut self,
        settings: Option<McpAppsClientSettings>,
    ) -> Self {
        self.mcp_apps_settings = settings;
        self
    }

    pub(crate) fn with_client_extension_runtime(
        mut self,
        runtime: Option<Arc<ClientExtensionRuntime>>,
    ) -> Self {
        self.client_extension_runtime = runtime;
        self
    }

    pub(crate) fn client_extension_runtime(&self) -> Option<&Arc<ClientExtensionRuntime>> {
        self.client_extension_runtime.as_ref()
    }

    pub(crate) fn client_extension_wire_settings(
        &self,
    ) -> Option<BTreeMap<String, serde_json::Value>> {
        self.client_extension_runtime
            .as_ref()
            .map(|runtime| runtime.client_wire_extensions())
    }

    pub(crate) fn negotiate_client_extensions_after_discovery(&mut self) -> McpResult<()> {
        if self.selected_era != Some(ProtocolEra::Modern2026) {
            self.negotiated_extensions = None;
            return Ok(());
        }
        let Some(runtime) = self.client_extension_runtime.as_ref() else {
            return Ok(());
        };
        let discovery = self.server_discovery.as_ref().ok_or_else(|| {
            McpError::internal_error(
                "Final client extension negotiation requires retained server/discover state",
            )
        })?;
        self.negotiated_extensions = Some(runtime.negotiate(discovery)?);
        Ok(())
    }

    pub(crate) fn admit_final_extension_method(
        &self,
        extension_id: &fastmcp_protocol::ExtensionId,
        method: &str,
    ) -> McpResult<()> {
        if self.selected_era != Some(ProtocolEra::Modern2026) {
            return Err(McpError::invalid_params(
                "Final client extensions are unavailable in exact MCP 2024-11-05",
            ));
        }
        let runtime = self.client_extension_runtime.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "No builder-owned final client extension registry is configured",
            )
        })?;
        let negotiated = self.negotiated_extensions.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "Final client extension settings were not negotiated by server/discover",
            )
        })?;
        runtime.admit_method(negotiated, extension_id, method)
    }

    pub(crate) fn set_mcp_apps_activation_receipt(
        &mut self,
        receipt: Option<McpAppsActivationReceipt>,
    ) {
        self.mcp_apps_activation_receipt = receipt;
    }

    pub(crate) fn mcp_apps_settings(&self) -> Option<&McpAppsClientSettings> {
        self.mcp_apps_settings.as_ref()
    }

    /// Returns the Apps receipt derived from the builder-owned generic
    /// registry when that registry owns the official Apps descriptor.
    ///
    /// This is deliberately distinct from the compatibility-only dedicated
    /// Apps settings path: once Apps travels through `extension_registry`,
    /// the frozen registry and its negotiated set are the only authority.
    pub(crate) fn generic_mcp_apps_activation_receipt(&self) -> Option<McpAppsActivationReceipt> {
        let runtime = self.client_extension_runtime.as_ref()?;
        runtime.configures_mcp_apps().then_some(())?;
        let negotiated = self.negotiated_extensions.as_ref()?;
        runtime.mcp_apps_activation_receipt(negotiated)
    }

    pub(crate) fn generic_mcp_apps_configured(&self) -> bool {
        self.client_extension_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.configures_mcp_apps())
    }

    /// Returns whether MCP Apps was bilaterally activated during final discovery.
    #[must_use]
    pub const fn mcp_apps_active(&self) -> bool {
        self.mcp_apps_activation_receipt.is_some()
    }

    /// Returns the immutable generic extension set negotiated from the final
    /// `server/discover` exchange, if this session selected MCP 2026-07-28
    /// and the builder installed a client extension registry.
    #[must_use]
    pub fn negotiated_extensions(&self) -> Option<&NegotiatedExtensionSet> {
        self.negotiated_extensions.as_ref()
    }

    /// Returns the immutable current Apps activation receipt, if modern
    /// discovery negotiated the official extension bilaterally.
    #[must_use]
    pub(crate) fn mcp_apps_activation_receipt(&self) -> Option<&McpAppsActivationReceipt> {
        self.mcp_apps_activation_receipt.as_ref()
    }

    pub(crate) fn set_protocol_plan(&mut self, protocol_plan: ClientProtocolPlan) {
        self.validate_protocol_plan(&protocol_plan)
            .expect("protocol plan must admit the negotiated era");
        self.protocol_plan = protocol_plan;
    }

    fn validate_protocol_plan(
        &self,
        protocol_plan: &ClientProtocolPlan,
    ) -> Result<(), ClientProtocolPlanError> {
        let Some(selected_era) = self.selected_era else {
            return Ok(());
        };
        if protocol_plan.policy().permits(selected_era.version()) {
            Ok(())
        } else {
            Err(ClientProtocolPlanError::IncompatibleSelectedEra {
                selected_era,
                policy: protocol_plan.policy(),
            })
        }
    }

    /// Returns the client info.
    #[must_use]
    pub fn client_info(&self) -> &ClientInfo {
        &self.client_info
    }

    /// Returns the client capabilities.
    #[must_use]
    pub fn client_capabilities(&self) -> &ClientCapabilities {
        &self.client_capabilities
    }

    /// Returns the server info.
    #[must_use]
    pub fn server_info(&self) -> &ServerInfo {
        &self.server_info
    }

    /// Returns the server capabilities.
    #[must_use]
    pub fn server_capabilities(&self) -> &ServerCapabilities {
        &self.server_capabilities
    }

    /// Returns the lossless final `server/discover` result when modern
    /// negotiation succeeded.
    ///
    /// A `None` value denotes the exact 2024-11-05 initialization path (or a
    /// session that has not yet negotiated). Callers using final MCP must use
    /// this result instead of the legacy [`Self::server_capabilities`] view.
    #[must_use]
    pub fn server_discovery(&self) -> Option<&ServerDiscoverResult> {
        self.server_discovery.as_ref()
    }

    /// Returns the negotiated protocol version.
    #[must_use]
    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    /// Returns the immutable era selected by the successful handshake.
    ///
    /// Placeholder sessions used before initialization have no selected era.
    #[must_use]
    pub const fn selected_era(&self) -> Option<ProtocolEra> {
        self.selected_era
    }

    #[must_use]
    pub const fn protocol_plan(&self) -> &ClientProtocolPlan {
        &self.protocol_plan
    }
}

/// Resolves the official Apps settings from a final discovery reply.
///
/// Absent or incompatible peer settings deliberately leave Apps inactive. The
/// public protocol decoder has already bounded the discovery capability shape;
/// this helper only interprets the registered official descriptor.
pub(crate) fn mcp_apps_activation_receipt(
    client_settings: Option<&McpAppsClientSettings>,
    discovery: &ServerDiscoverResult,
) -> Option<McpAppsActivationReceipt> {
    let client_settings = client_settings?;
    let capabilities = serde_json::to_value(discovery.capabilities()).ok()?;
    let server_settings = capabilities
        .get("extensions")
        .and_then(serde_json::Value::as_object)
        .and_then(|extensions| extensions.get(official_mcp_apps_extension_id().as_str()))
        .cloned()?;
    let server_settings = ExtensionSettings::new(server_settings).ok()?;
    let mut registry = ExtensionDescriptorRegistry::new();
    let apps_extension = register_official_mcp_apps_extension(&mut registry).ok()?;
    registry.freeze().ok()?;

    let mut local = ExtensionLocalEnablement::default();
    local.enable(apps_extension.clone());
    let client = ClientExtensionDiscovery {
        extensions: BTreeMap::from([(
            apps_extension.clone(),
            client_settings.to_extension_settings(),
        )]),
    };
    let server = ServerExtensionDiscovery {
        extensions: BTreeMap::from([(apps_extension, server_settings)]),
    };
    let mut resolver = official_mcp_apps_negotiation_resolver();
    registry
        .negotiate(
            ProtocolEra::Modern2026,
            &local,
            &client,
            &server,
            &mut resolver,
        )
        .ok()?
        .mcp_apps_activation_receipt(&registry)
}

/// Compatibility predicate for callers that only need to advertise Apps over
/// an already-negotiated HTTP connection. Session-bearing clients retain the
/// opaque receipt through [`mcp_apps_activation_receipt`] instead.
pub(crate) fn resolve_mcp_apps_activation(
    client_settings: Option<&McpAppsClientSettings>,
    discovery: &ServerDiscoverResult,
) -> bool {
    mcp_apps_activation_receipt(client_settings, discovery).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apps_discovery(server_settings: serde_json::Value) -> ServerDiscoverResult {
        serde_json::from_value(serde_json::json!({
            "resultType": "complete",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {
                "extensions": {
                    "io.modelcontextprotocol/ui": server_settings
                }
            },
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {"name": "apps-server", "version": "1.0"}
            },
            "ttlMs": 0,
            "cacheScope": "private"
        }))
        .expect("valid final Apps discovery reply")
    }

    #[test]
    fn mcp_apps_activation_requires_html_mime_with_the_same_server_marker() {
        let discovery = apps_discovery(serde_json::json!({}));
        let active = McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
            .expect("valid Apps MIME settings");
        let inactive = McpAppsClientSettings::new(vec!["text/html".to_owned()])
            .expect("valid non-Apps MIME settings");

        assert!(resolve_mcp_apps_activation(Some(&active), &discovery));
        assert!(
            !resolve_mcp_apps_activation(Some(&inactive), &discovery),
            "only the advertised Apps HTML MIME differs"
        );
    }

    #[test]
    fn generic_apps_runtime_derives_the_same_frozen_activation_receipt() {
        let mut registry = ExtensionDescriptorRegistry::new();
        let apps_id = register_official_mcp_apps_extension(&mut registry)
            .expect("official Apps descriptor registers before builder freeze");
        let settings = McpAppsClientSettings::new(vec!["text/html;profile=mcp-app".to_owned()])
            .expect("Apps HTML profile settings are valid");
        let runtime = ClientExtensionRuntime::new(
            registry,
            ClientExtensionDiscovery {
                extensions: std::collections::BTreeMap::from([(
                    apps_id,
                    settings.to_extension_settings(),
                )]),
            },
            official_mcp_apps_negotiation_resolver,
        )
        .expect("generic builder runtime freezes the official Apps descriptor");
        let negotiated = runtime
            .negotiate(&apps_discovery(serde_json::json!({})))
            .expect("generic Apps settings negotiate against the empty server marker");

        assert!(runtime.configures_mcp_apps());
        assert!(
            runtime.mcp_apps_activation_receipt(&negotiated).is_some(),
            "the generic frozen registry, rather than a second Apps constructor, owns activation"
        );
    }

    use fastmcp_protocol::protocol_policy::{LEGACY_PROTOCOL_VERSION, MODERN_PROTOCOL_VERSION};
    use fastmcp_protocol::{PromptsCapability, ResourcesCapability, ToolsCapability};

    fn test_session_with_protocol_version(protocol_version: &str) -> ClientSession {
        try_test_session_with_protocol_version(protocol_version)
            .expect("test sessions use an exact supported protocol version")
    }

    fn try_test_session_with_protocol_version(
        protocol_version: &str,
    ) -> Result<ClientSession, ProtocolVersionError> {
        ClientSession::try_new(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            ServerInfo {
                name: "test-server".to_string(),
                version: "2.0.0".to_string(),
            },
            ServerCapabilities {
                tools: Some(ToolsCapability { list_changed: true }),
                resources: Some(ResourcesCapability {
                    subscribe: true,
                    list_changed: false,
                }),
                prompts: Some(PromptsCapability {
                    list_changed: false,
                }),
                logging: None,
                tasks: None,
            },
            protocol_version.to_owned(),
        )
    }

    fn test_session() -> ClientSession {
        test_session_with_protocol_version(LEGACY_PROTOCOL_VERSION)
    }

    #[test]
    fn session_client_info() {
        let session = test_session();
        assert_eq!(session.client_info().name, "test-client");
        assert_eq!(session.client_info().version, "1.0.0");
    }

    #[test]
    fn session_client_capabilities() {
        let session = test_session();
        let caps = session.client_capabilities();
        assert!(caps.sampling.is_none());
        assert!(caps.elicitation.is_none());
        assert!(caps.roots.is_none());
    }

    #[test]
    fn session_server_info() {
        let session = test_session();
        assert_eq!(session.server_info().name, "test-server");
        assert_eq!(session.server_info().version, "2.0.0");
    }

    #[test]
    fn session_server_capabilities() {
        let session = test_session();
        let caps = session.server_capabilities();
        assert!(caps.tools.is_some());
        assert!(caps.tools.as_ref().unwrap().list_changed);
        assert!(caps.resources.is_some());
        assert!(caps.resources.as_ref().unwrap().subscribe);
        assert!(!caps.resources.as_ref().unwrap().list_changed);
        assert!(caps.prompts.is_some());
        assert!(caps.logging.is_none());
        assert!(caps.tasks.is_none());
    }

    #[test]
    fn session_protocol_version() {
        let session = test_session();
        assert_eq!(session.protocol_version(), LEGACY_PROTOCOL_VERSION);
    }

    #[test]
    fn session_default_protocol_plan_remains_auto_after_era_selection() {
        let modern = test_session_with_protocol_version(MODERN_PROTOCOL_VERSION);
        let legacy = test_session();

        assert_eq!(modern.selected_era(), Some(ProtocolEra::Modern2026));
        assert_eq!(legacy.selected_era(), Some(ProtocolEra::Legacy2024));
        assert_eq!(modern.protocol_plan().policy(), ProtocolPolicy::Auto);
        assert_eq!(legacy.protocol_plan().policy(), ProtocolPolicy::Auto);
    }

    #[test]
    fn session_rejects_plan_that_forbids_the_negotiated_era() {
        let error = test_session()
            .try_with_protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
            .expect_err("a modern-only plan cannot be applied to a legacy session");

        assert_eq!(
            error,
            ClientProtocolPlanError::IncompatibleSelectedEra {
                selected_era: ProtocolEra::Legacy2024,
                policy: ProtocolPolicy::ModernOnly,
            }
        );
    }

    #[test]
    fn session_try_new_preserves_admitted_configured_policy() {
        let session = try_test_session_with_protocol_version(LEGACY_PROTOCOL_VERSION)
            .expect("the supported legacy version constructs a session")
            .try_with_protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly))
            .expect("the configured legacy-only policy admits the legacy session");

        assert_eq!(session.selected_era(), Some(ProtocolEra::Legacy2024));
        assert_eq!(session.protocol_plan().policy(), ProtocolPolicy::LegacyOnly);
    }

    #[test]
    fn session_try_new_rejects_unsupported_protocol_version() {
        let error = try_test_session_with_protocol_version("2025-11-25")
            .expect_err("only the peer version differs from the supported positive case");

        assert_eq!(
            error,
            ProtocolVersionError::UnsupportedVersion {
                received: "2025-11-25".to_string(),
            }
        );
    }

    #[test]
    fn session_with_sampling_capabilities() {
        let session = ClientSession::try_new(
            ClientInfo {
                name: "sampler".to_string(),
                version: "0.1.0".to_string(),
            },
            ClientCapabilities {
                sampling: Some(fastmcp_protocol::SamplingCapability {}),
                elicitation: None,
                roots: None,
            },
            ServerInfo {
                name: "srv".to_string(),
                version: "1.0.0".to_string(),
            },
            ServerCapabilities::default(),
            "2024-11-05".to_string(),
        )
        .expect("exact supported protocol version");
        assert!(session.client_capabilities().sampling.is_some());
    }

    #[test]
    fn session_with_empty_server_capabilities() {
        let session = ClientSession::new_placeholder(
            ClientInfo {
                name: "c".to_string(),
                version: "0.1.0".to_string(),
            },
            ClientCapabilities::default(),
            ServerInfo {
                name: "s".to_string(),
                version: "0.1.0".to_string(),
            },
            ServerCapabilities::default(),
        );
        assert!(session.server_capabilities().tools.is_none());
        assert!(session.server_capabilities().resources.is_none());
        assert!(session.server_capabilities().prompts.is_none());
        assert!(session.server_capabilities().logging.is_none());
        assert!(session.server_capabilities().tasks.is_none());
        assert!(session.protocol_version().is_empty());
    }
}
