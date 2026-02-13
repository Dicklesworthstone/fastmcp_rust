//! Proxy/composition support for MCP servers.
//!
//! This module provides lightweight proxy handlers that forward tool/resource/prompt
//! calls to another MCP server via a backend client.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use fastmcp_client::Client;
use fastmcp_core::{McpContext, McpError, McpResult};
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
        if self.server_capabilities().tools.is_none() {
            return Ok(Vec::new());
        }
        Client::list_tools(self)
    }

    fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        if self.server_capabilities().resources.is_none() {
            return Ok(Vec::new());
        }
        Client::list_resources(self)
    }

    fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
        if self.server_capabilities().resources.is_none() {
            return Ok(Vec::new());
        }
        Client::list_resource_templates(self)
    }

    fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
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
}

impl ProxyClient {
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
        }
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

    fn call_tool(
        &self,
        ctx: &McpContext,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<Vec<Content>> {
        ctx.checkpoint()?;
        self.with_backend(|backend| {
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
        })
    }

    fn read_resource(&self, ctx: &McpContext, uri: &str) -> McpResult<Vec<ResourceContent>> {
        ctx.checkpoint()?;
        self.with_backend(|backend| backend.read_resource(uri))
    }

    fn get_prompt(
        &self,
        ctx: &McpContext,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        ctx.checkpoint()?;
        self.with_backend(|backend| backend.get_prompt(name, arguments))
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
    template: Option<ResourceTemplate>,
    client: ProxyClient,
}

impl ProxyResourceHandler {
    pub(crate) fn new(resource: Resource, client: ProxyClient) -> Self {
        let external_uri = resource.uri.clone();
        Self {
            resource,
            external_uri,
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
            template: None,
            client,
        }
    }

    pub(crate) fn from_template(template: ResourceTemplate, client: ProxyClient) -> Self {
        let external_uri = template.uri_template.clone();
        Self {
            resource: resource_from_template(&template),
            external_uri,
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
        // For templated resources with a prefix, we need to strip the prefix
        // to forward the correct URI to the external server.
        //
        // If the incoming URI matches our prefixed pattern (e.g., "ext/file://..."),
        // strip the prefix to get the original URI (e.g., "file://...").
        let external_uri = if uri.starts_with(&format!(
            "{}/",
            self.resource.uri.split('/').next().unwrap_or("")
        )) {
            // Strip the prefix (everything before and including the first '/')
            uri.splitn(2, '/').nth(1).unwrap_or(uri)
        } else {
            // No prefix match, use as-is
            uri
        };
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

    use asupersync::Cx;
    use fastmcp_core::McpContext;
    use fastmcp_protocol::{Content, Prompt, PromptMessage, Resource, ResourceContent, Tool};

    use super::{ProxyBackend, ProxyCatalog, ProxyClient, ProxyPromptHandler, ProxyToolHandler};
    use crate::handler::{PromptHandler, ToolHandler};

    #[derive(Default)]
    struct TestState {
        last_tool: Option<(String, serde_json::Value)>,
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

        fn read_resource(&mut self, _uri: &str) -> fastmcp_core::McpResult<Vec<ResourceContent>> {
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
    }

    #[test]
    fn proxy_resource_handler_read_with_uri_no_prefix_match() {
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
        // URI without prefix match - used as-is
        let result = handler
            .read_with_uri(&ctx, "other://uri", &params)
            .expect("read ok");
        assert_eq!(result.len(), 1);
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
    }

    #[test]
    fn proxy_resource_handler_from_template_with_prefix_read_with_uri() {
        use super::ProxyResourceHandler;
        use crate::handler::ResourceHandler;
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

        let ctx = McpContext::new(Cx::for_testing(), 1);
        let mut params = HashMap::new();
        params.insert("table".to_string(), "orders".to_string());
        // Prefixed URI
        let result = handler
            .read_with_uri(&ctx, "remote/db://orders", &params)
            .expect("read ok");
        assert_eq!(result.len(), 1);
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
