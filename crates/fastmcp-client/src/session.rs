//! Client session state.

use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::protocol_policy::{
    HttpEndpointBundle, HttpEndpointBundleError, ProtocolPolicy,
};
use fastmcp_protocol::{ClientCapabilities, ClientInfo, ServerCapabilities, ServerInfo};

/// Immutable transport policy and trusted endpoint configuration for one client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientProtocolPlan {
    policy: ProtocolPolicy,
    http_endpoints: Option<HttpEndpointBundle>,
}

impl ClientProtocolPlan {
    #[must_use]
    pub const fn stdio(policy: ProtocolPolicy) -> Self {
        Self {
            policy,
            http_endpoints: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn http(
        policy: ProtocolPolicy,
        modern_post: Option<CanonicalHttpUrl>,
        legacy_sse: Option<CanonicalHttpUrl>,
        legacy_message_post: Option<CanonicalHttpUrl>,
        credential_partition: String,
        transport_profile: String,
        configuration_generation: u64,
        legacy_receipt_generation: u64,
    ) -> Result<Self, HttpEndpointBundleError> {
        Ok(Self {
            policy,
            http_endpoints: Some(HttpEndpointBundle::new(
                policy,
                modern_post,
                legacy_sse,
                legacy_message_post,
                credential_partition,
                transport_profile,
                configuration_generation,
                legacy_receipt_generation,
            )?),
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

    pub(crate) fn validate_for_stdio(&self) -> Result<(), ClientProtocolPlanError> {
        if self.policy.requires_legacy_adapter() {
            return Err(ClientProtocolPlanError::LegacyAdapterUnavailable {
                policy: self.policy,
            });
        }
        Ok(())
    }
}

/// Typed refusal raised before a client process can be spawned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProtocolPlanError {
    /// Auto and legacy-only require the exact installed LEG-03 adapter.
    LegacyAdapterUnavailable { policy: ProtocolPolicy },
}

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
    /// Negotiated protocol version.
    protocol_version: String,
    /// Immutable policy and configured endpoint bundle for this client.
    protocol_plan: ClientProtocolPlan,
}

impl ClientSession {
    /// Creates a new client session after successful initialization.
    #[must_use]
    pub fn new(
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        server_info: ServerInfo,
        server_capabilities: ServerCapabilities,
        protocol_version: String,
    ) -> Self {
        Self {
            client_info,
            client_capabilities,
            server_info,
            server_capabilities,
            protocol_version,
            protocol_plan: ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
        }
    }

    #[must_use]
    pub fn with_protocol_plan(mut self, protocol_plan: ClientProtocolPlan) -> Self {
        self.protocol_plan = protocol_plan;
        self
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

    /// Returns the negotiated protocol version.
    #[must_use]
    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    #[must_use]
    pub const fn protocol_plan(&self) -> &ClientProtocolPlan {
        &self.protocol_plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{PromptsCapability, ResourcesCapability, ToolsCapability};

    fn test_session() -> ClientSession {
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
            "2024-11-05".to_string(),
        )
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
        assert_eq!(session.protocol_version(), "2024-11-05");
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
