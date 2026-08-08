//! Client session state.

use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::protocol_policy::{
    HttpEndpointBundle, HttpEndpointBundleError, ProtocolEra, ProtocolPolicy, ProtocolVersion,
    ProtocolVersionError,
};
use fastmcp_protocol::{
    ClientCapabilities, ClientInfo, ServerCapabilities, ServerDiscoverResult, ServerInfo,
};

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
        ProtocolVersion::parse(&protocol_version)?;
        Ok(Self::new(
            client_info,
            client_capabilities,
            server_info,
            server_capabilities,
            protocol_version,
        ))
    }

    /// Creates a new client session after successful initialization.
    ///
    /// An empty version is reserved for pre-initialization placeholder state.
    /// Any nonempty version must be one of the two exact supported revisions.
    ///
    /// # Panics
    ///
    /// Panics for a nonempty unsupported version. Prefer [`Self::try_new`]
    /// when the version was received from a peer.
    #[must_use]
    pub fn new(
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        server_info: ServerInfo,
        server_capabilities: ServerCapabilities,
        protocol_version: String,
    ) -> Self {
        let selected_era = if protocol_version.is_empty() {
            None
        } else {
            Some(
                ProtocolVersion::parse(&protocol_version)
                    .expect("negotiated sessions require a supported protocol version")
                    .era(),
            )
        };
        Self {
            client_info,
            client_capabilities,
            server_info,
            server_capabilities,
            server_discovery: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::protocol_policy::{LEGACY_PROTOCOL_VERSION, MODERN_PROTOCOL_VERSION};
    use fastmcp_protocol::{PromptsCapability, ResourcesCapability, ToolsCapability};

    fn test_session_with_protocol_version(protocol_version: &str) -> ClientSession {
        ClientSession::new(
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
    fn session_accepts_auto_plan_for_the_negotiated_era() {
        let session = test_session()
            .try_with_protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::Auto))
            .expect("auto admits the selected legacy era");

        assert_eq!(session.selected_era(), Some(ProtocolEra::Legacy2024));
        assert_eq!(session.protocol_plan().policy(), ProtocolPolicy::Auto);
    }

    #[test]
    fn session_try_new_rejects_unsupported_protocol_version() {
        let error = ClientSession::try_new(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            ServerInfo {
                name: "test-server".to_string(),
                version: "2.0.0".to_string(),
            },
            ServerCapabilities::default(),
            "2025-11-25".to_string(),
        )
        .expect_err("unsupported versions must not construct a negotiated session");

        assert_eq!(
            error,
            ProtocolVersionError::UnsupportedVersion {
                received: "2025-11-25".to_string(),
            }
        );
    }

    #[test]
    #[should_panic(expected = "negotiated sessions require a supported protocol version")]
    fn session_new_rejects_unsupported_protocol_version() {
        let _ = test_session_with_protocol_version("2025-11-25");
    }

    #[test]
    fn session_with_sampling_capabilities() {
        let session = ClientSession::new(
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
        );
        assert!(session.client_capabilities().sampling.is_some());
    }

    #[test]
    fn session_with_empty_server_capabilities() {
        let session = ClientSession::new(
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
            String::new(),
        );
        assert!(session.server_capabilities().tools.is_none());
        assert!(session.server_capabilities().resources.is_none());
        assert!(session.server_capabilities().prompts.is_none());
        assert!(session.server_capabilities().logging.is_none());
        assert!(session.server_capabilities().tasks.is_none());
        assert!(session.protocol_version().is_empty());
    }
}
