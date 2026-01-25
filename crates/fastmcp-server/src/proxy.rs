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
pub type ProgressCallback<'a> = &'a mut dyn FnMut(f64, Option<f64>, Option<&str>);

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
        Client::call_tool_with_progress(self, name, arguments, on_progress)
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
        self.with_backend(|backend| backend.call_tool(name, arguments))
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
    tool: Tool,
    client: ProxyClient,
}

impl ProxyToolHandler {
    pub(crate) fn new(tool: Tool, client: ProxyClient) -> Self {
        Self { tool, client }
    }
}

impl ToolHandler for ProxyToolHandler {
    fn definition(&self) -> Tool {
        self.tool.clone()
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        self.client.call_tool(ctx, &self.tool.name, arguments)
    }
}

pub(crate) struct ProxyResourceHandler {
    resource: Resource,
    template: Option<ResourceTemplate>,
    client: ProxyClient,
}

impl ProxyResourceHandler {
    pub(crate) fn new(resource: Resource, client: ProxyClient) -> Self {
        Self {
            resource,
            template: None,
            client,
        }
    }

    pub(crate) fn from_template(template: ResourceTemplate, client: ProxyClient) -> Self {
        Self {
            resource: resource_from_template(&template),
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
        self.client.read_resource(ctx, &self.resource.uri)
    }

    fn read_with_uri(
        &self,
        ctx: &McpContext,
        uri: &str,
        _params: &UriParams,
    ) -> McpResult<Vec<ResourceContent>> {
        self.client.read_resource(ctx, uri)
    }
}

pub(crate) struct ProxyPromptHandler {
    prompt: Prompt,
    client: ProxyClient,
}

impl ProxyPromptHandler {
    pub(crate) fn new(prompt: Prompt, client: ProxyClient) -> Self {
        Self { prompt, client }
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
        self.client.get_prompt(ctx, &self.prompt.name, arguments)
    }
}

fn resource_from_template(template: &ResourceTemplate) -> Resource {
    Resource {
        uri: template.uri_template.clone(),
        name: template.name.clone(),
        description: template.description.clone(),
        mime_type: template.mime_type.clone(),
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
            on_progress(0.5, Some(1.0), Some("half"));
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
            }],
            resources: vec![Resource {
                uri: "test://resource".to_string(),
                name: "resource".to_string(),
                description: None,
                mime_type: None,
            }],
            prompts: vec![Prompt {
                name: "prompt".to_string(),
                description: None,
                arguments: Vec::new(),
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
}
