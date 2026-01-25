//! Comprehensive tests for the MCP server using Lab runtime patterns.
//!
//! These tests verify:
//! - Request/response cycle
//! - Tool invocation with cancellation
//! - Resource reading with budget exhaustion
//! - Multi-handler registration
//! - Error handling

use std::collections::HashMap;

use asupersync::{Budget, Cx};
use fastmcp_core::{McpContext, McpError, McpResult, SessionState};
use fastmcp_protocol::{
    CallToolParams, CancelledParams, ClientCapabilities, ClientInfo, Content, GetPromptParams,
    InitializeParams, Prompt, PromptArgument, PromptMessage, ReadResourceParams, RequestId,
    Resource, ResourceContent, ResourceTemplate, Role, ServerCapabilities, ServerInfo, Tool,
};

use crate::handler::{PromptHandler, ResourceHandler, ToolHandler, UriParams};
use crate::router::Router;
use crate::session::Session;
use crate::{NotificationSender, Server};

// ============================================================================
// Test Tool Handlers
// ============================================================================

/// A simple tool that greets a user.
struct GreetTool;

impl ToolHandler for GreetTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "greet".to_string(),
            description: Some("Greets a user by name".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"}
                },
                "required": ["name"]
            }),
        }
    }

    fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let name = arguments
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("World");
        Ok(vec![Content::Text {
            text: format!("Hello, {name}!"),
        }])
    }
}

/// A tool that checks cancellation.
struct CancellationCheckTool;

impl ToolHandler for CancellationCheckTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "cancellation_check".to_string(),
            description: Some("Tool that checks cancellation status".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        // Check for cancellation
        if ctx.is_cancelled() {
            return Err(McpError::request_cancelled());
        }
        Ok(vec![Content::Text {
            text: "Not cancelled".to_string(),
        }])
    }
}

/// A tool that simulates slow work.
struct SlowTool;

impl ToolHandler for SlowTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "slow_tool".to_string(),
            description: Some("Simulates a slow operation".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
        }
    }

    fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        // Simulate work with checkpoint checks
        for i in 0..5 {
            if ctx.checkpoint().is_err() {
                return Err(McpError::request_cancelled());
            }
            // Normally we'd do work here
            let _ = i;
        }
        Ok(vec![Content::Text {
            text: "Slow work completed".to_string(),
        }])
    }
}

/// A tool that returns an error.
struct ErrorTool;

impl ToolHandler for ErrorTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "error_tool".to_string(),
            description: Some("Always returns an error".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Err(McpError::internal_error("Intentional error for testing"))
    }
}

// ============================================================================
// Test Resource Handlers
// ============================================================================

/// A simple static resource.
struct StaticResource {
    uri: String,
    content: String,
}

impl ResourceHandler for StaticResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: self.uri.clone(),
            name: "Static Resource".to_string(),
            description: Some("A static test resource".to_string()),
            mime_type: Some("text/plain".to_string()),
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Ok(vec![ResourceContent {
            uri: self.uri.clone(),
            mime_type: Some("text/plain".to_string()),
            text: Some(self.content.clone()),
            blob: None,
        }])
    }
}

/// A resource that checks cancellation.
struct CancellableResource;

impl ResourceHandler for CancellableResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: "resource://cancellable".to_string(),
            name: "Cancellable Resource".to_string(),
            description: Some("A resource that checks cancellation".to_string()),
            mime_type: Some("text/plain".to_string()),
        }
    }

    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        if ctx.is_cancelled() {
            return Err(McpError::request_cancelled());
        }
        Ok(vec![ResourceContent {
            uri: "resource://cancellable".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some("Resource content".to_string()),
            blob: None,
        }])
    }
}

/// A resource with a URI template that echoes the matched parameter.
struct TemplateResource;

impl ResourceHandler for TemplateResource {
    fn definition(&self) -> Resource {
        Resource {
            uri: "resource://{id}".to_string(),
            name: "Template Resource".to_string(),
            description: Some("Template resource for tests".to_string()),
            mime_type: Some("text/plain".to_string()),
        }
    }

    fn template(&self) -> Option<ResourceTemplate> {
        Some(ResourceTemplate {
            uri_template: "resource://{id}".to_string(),
            name: "Template Resource".to_string(),
            description: Some("Template resource for tests".to_string()),
            mime_type: Some("text/plain".to_string()),
        })
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Err(McpError::invalid_params(
            "uri parameters required for template resource",
        ))
    }

    fn read_with_uri(
        &self,
        _ctx: &McpContext,
        uri: &str,
        params: &UriParams,
    ) -> McpResult<Vec<ResourceContent>> {
        let id = params
            .get("id")
            .ok_or_else(|| McpError::invalid_params("missing uri parameter: id"))?;
        Ok(vec![ResourceContent {
            uri: uri.to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some(format!("Template {id}")),
            blob: None,
        }])
    }
}

// ============================================================================
// Test Prompt Handlers
// ============================================================================

/// A simple greeting prompt.
struct GreetingPrompt;

impl PromptHandler for GreetingPrompt {
    fn definition(&self) -> Prompt {
        Prompt {
            name: "greeting".to_string(),
            description: Some("A simple greeting prompt".to_string()),
            arguments: vec![PromptArgument {
                name: "name".to_string(),
                description: Some("Name to greet".to_string()),
                required: true,
            }],
        }
    }

    fn get(
        &self,
        _ctx: &McpContext,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        let name = arguments.get("name").map_or("User", String::as_str);
        Ok(vec![PromptMessage {
            role: Role::User,
            content: Content::Text {
                text: format!("Please greet {name} warmly."),
            },
        }])
    }
}

// ============================================================================
// Router Tests
// ============================================================================

#[cfg(test)]
mod router_tests {
    use super::*;

    /// Creates a test router with all handlers registered.
    fn create_test_router() -> Router {
        let mut router = Router::new();

        // Register tools
        router.add_tool(GreetTool);
        router.add_tool(CancellationCheckTool);
        router.add_tool(SlowTool);
        router.add_tool(ErrorTool);

        // Register resources
        router.add_resource(StaticResource {
            uri: "resource://test".to_string(),
            content: "Test content".to_string(),
        });
        router.add_resource(CancellableResource);
        router.add_resource(TemplateResource);

        // Register resource templates
        router.add_resource_template(ResourceTemplate {
            uri_template: "resource://{name}".to_string(),
            name: "Manual Template".to_string(),
            description: Some("Resource template for manual listing".to_string()),
            mime_type: Some("text/plain".to_string()),
        });

        // Register prompts
        router.add_prompt(GreetingPrompt);

        router
    }

    /// Creates a test session.
    fn create_test_session() -> Session {
        Session::new(
            ServerInfo {
                name: "test-server".to_string(),
                version: "1.0.0".to_string(),
            },
            ServerCapabilities::default(),
        )
    }

    #[test]
    fn test_router_tool_list() {
        let router = create_test_router();
        let tools = router.tools();

        assert_eq!(tools.len(), 4);

        let tool_names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(tool_names.contains(&"greet"));
        assert!(tool_names.contains(&"cancellation_check"));
        assert!(tool_names.contains(&"slow_tool"));
        assert!(tool_names.contains(&"error_tool"));
    }

    #[test]
    fn test_router_resource_list() {
        let router = create_test_router();
        let resources = router.resources();

        assert_eq!(resources.len(), 2);

        let resource_uris: Vec<_> = resources.iter().map(|r| r.uri.as_str()).collect();
        assert!(resource_uris.contains(&"resource://test"));
        assert!(resource_uris.contains(&"resource://cancellable"));
    }

    #[test]
    fn test_router_resource_template_list() {
        let router = create_test_router();
        let templates = router.resource_templates();

        assert_eq!(templates.len(), 2);

        let template_uris: Vec<_> = templates
            .iter()
            .map(|template| template.uri_template.as_str())
            .collect();
        assert!(template_uris.contains(&"resource://{id}"));
        assert!(template_uris.contains(&"resource://{name}"));
    }

    #[test]
    fn test_router_prompt_list() {
        let router = create_test_router();
        let prompts = router.prompts();

        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "greeting");
    }

    #[test]
    fn test_notification_does_not_return_response() {
        let server = Server::new("test-server", "1.0.0").build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();

        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let sender: NotificationSender = std::sync::Arc::new(|_| {});
        let params = CancelledParams {
            request_id: RequestId::Number(1),
            reason: Some("unit test".to_string()),
            await_cleanup: None,
        };
        let request = fastmcp_protocol::JsonRpcRequest::notification(
            "notifications/cancelled",
            Some(serde_json::to_value(params).unwrap()),
        );

        let response = server.handle_request(&cx, &mut session, request, &sender);
        assert!(response.is_none());
    }

    #[test]
    fn test_cancelled_notification_marks_request_cancelled() {
        let server = Server::new("test-server", "1.0.0").build();
        let request_id = RequestId::Number(99);
        let cx = Cx::for_testing();

        {
            let mut guard = server
                .active_requests
                .lock()
                .expect("active_requests lock poisoned");
            guard.insert(request_id.clone(), cx.clone());
        }

        let params = CancelledParams {
            request_id: request_id.clone(),
            reason: Some("test cancellation".to_string()),
            await_cleanup: None,
        };
        server.handle_cancelled_notification(params);

        assert!(cx.is_cancel_requested());
    }

    #[test]
    fn test_resources_subscribe_and_unsubscribe() {
        let server = Server::new("test-server", "1.0.0")
            .resource(StaticResource {
                uri: "resource://test".to_string(),
                content: "Test content".to_string(),
            })
            .build();
        let cx = Cx::for_testing();
        let mut session = create_test_session();

        session.initialize(
            ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        let sender: NotificationSender = std::sync::Arc::new(|_| {});
        let subscribe = fastmcp_protocol::JsonRpcRequest::new(
            "resources/subscribe",
            Some(
                serde_json::to_value(fastmcp_protocol::SubscribeResourceParams {
                    uri: "resource://test".to_string(),
                })
                .unwrap(),
            ),
            1i64,
        );
        let response = server
            .handle_request(&cx, &mut session, subscribe, &sender)
            .expect("response");
        assert!(response.error.is_none());
        assert!(session.is_resource_subscribed("resource://test"));

        let unsubscribe = fastmcp_protocol::JsonRpcRequest::new(
            "resources/unsubscribe",
            Some(
                serde_json::to_value(fastmcp_protocol::UnsubscribeResourceParams {
                    uri: "resource://test".to_string(),
                })
                .unwrap(),
            ),
            2i64,
        );
        let response = server
            .handle_request(&cx, &mut session, unsubscribe, &sender)
            .expect("response");
        assert!(response.error.is_none());
        assert!(!session.is_resource_subscribed("resource://test"));
    }

    #[test]
    fn test_handle_initialize() {
        let router = create_test_router();
        let mut session = create_test_session();
        let cx = Cx::for_testing();

        let params = InitializeParams {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ClientCapabilities::default(),
            client_info: ClientInfo {
                name: "test-client".to_string(),
                version: "1.0.0".to_string(),
            },
        };

        let result = router.handle_initialize(&cx, &mut session, params, Some("Test instructions"));

        assert!(result.is_ok());
        let init_result = result.unwrap();
        assert_eq!(init_result.server_info.name, "test-server");
        assert_eq!(
            init_result.instructions,
            Some("Test instructions".to_string())
        );
        assert!(session.is_initialized());
    }

    #[test]
    fn test_handle_tools_call_success() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": "Alice"})),
            meta: None,
        };

        let result = router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None);

        assert!(result.is_ok());
        let call_result = result.unwrap();
        assert!(!call_result.is_error);
        assert_eq!(call_result.content.len(), 1);

        assert!(matches!(call_result.content[0], Content::Text { .. }));
        let Content::Text { text } = &call_result.content[0] else {
            return;
        };
        assert_eq!(text, "Hello, Alice!");
    }

    #[test]
    fn test_handle_tools_call_not_found() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = CallToolParams {
            name: "nonexistent".to_string(),
            arguments: None,
            meta: None,
        };

        let result = router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("nonexistent"));
    }

    #[test]
    fn test_handle_tools_call_with_error() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = CallToolParams {
            name: "error_tool".to_string(),
            arguments: None,
            meta: None,
        };

        let result = router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None);

        // Tool errors are returned as content with is_error=true
        assert!(result.is_ok());
        let call_result = result.unwrap();
        assert!(call_result.is_error);
        assert_eq!(call_result.content.len(), 1);
    }

    #[test]
    fn test_handle_tools_call_with_cancellation() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let budget = Budget::INFINITE;

        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": "Alice"})),
            meta: None,
        };

        let result = router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None);

        // Request should be cancelled before handler runs
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_tools_call_with_exhausted_budget() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::unlimited().with_poll_quota(0);

        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": "Alice"})),
            meta: None,
        };

        let result = router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None);

        // Request should fail due to exhausted budget
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("budget") || err.message.contains("exhausted"));
    }

    #[test]
    fn test_handle_resources_read_success() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = ReadResourceParams {
            uri: "resource://test".to_string(),
            meta: None,
        };

        let result =
            router.handle_resources_read(&cx, 1, &params, &budget, SessionState::new(), None);

        assert!(result.is_ok());
        let read_result = result.unwrap();
        assert_eq!(read_result.contents.len(), 1);
        assert_eq!(
            read_result.contents[0].text,
            Some("Test content".to_string())
        );
    }

    #[test]
    fn test_handle_resources_read_template_match() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = ReadResourceParams {
            uri: "resource://abc".to_string(),
            meta: None,
        };

        let result =
            router.handle_resources_read(&cx, 1, &params, &budget, SessionState::new(), None);

        assert!(result.is_ok(), "Expected Ok, got Err: {:?}", result.err());
        let read_result = result.unwrap();
        assert_eq!(
            read_result.contents[0].text,
            Some("Template abc".to_string())
        );
    }

    #[test]
    fn test_handle_resources_read_not_found() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        // Use a scheme that doesn't match any registered resources or templates
        let params = ReadResourceParams {
            uri: "file://nonexistent".to_string(),
            meta: None,
        };

        let result =
            router.handle_resources_read(&cx, 1, &params, &budget, SessionState::new(), None);

        assert!(result.is_err());
    }

    #[test]
    fn test_handle_resources_read_with_cancellation() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let budget = Budget::INFINITE;

        let params = ReadResourceParams {
            uri: "resource://test".to_string(),
            meta: None,
        };

        let result =
            router.handle_resources_read(&cx, 1, &params, &budget, SessionState::new(), None);

        // Should be cancelled
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_prompts_get_success() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = GetPromptParams {
            name: "greeting".to_string(),
            arguments: Some({
                let mut map = HashMap::new();
                map.insert("name".to_string(), "Bob".to_string());
                map
            }),
            meta: None,
        };

        let result = router.handle_prompts_get(&cx, 1, params, &budget, SessionState::new(), None);

        assert!(result.is_ok());
        let get_result = result.unwrap();
        assert_eq!(get_result.messages.len(), 1);

        assert!(matches!(get_result.messages[0].content, Content::Text { .. }));
        let Content::Text { text } = &get_result.messages[0].content else {
            return;
        };
        assert!(text.contains("Bob"));
    }

    #[test]
    fn test_handle_prompts_get_not_found() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let params = GetPromptParams {
            name: "nonexistent".to_string(),
            arguments: None,
            meta: None,
        };

        let result = router.handle_prompts_get(&cx, 1, params, &budget, SessionState::new(), None);

        assert!(result.is_err());
    }

    #[test]
    fn test_handle_tools_call_validation_missing_required() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        // greet tool requires 'name' field, so passing empty object should fail validation
        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({})),
            meta: None,
        };

        let result = router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("validation") || err.message.contains("required"));
    }

    #[test]
    fn test_handle_tools_call_validation_wrong_type() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        // greet tool expects 'name' to be a string, not a number
        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": 123})),
            meta: None,
        };

        let result = router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("validation") || err.message.contains("type"));
    }

    #[test]
    fn test_handle_tools_call_validation_passes() {
        let router = create_test_router();
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        // Valid arguments that satisfy the schema
        let params = CallToolParams {
            name: "greet".to_string(),
            arguments: Some(serde_json::json!({"name": "Alice"})),
            meta: None,
        };

        let result = router.handle_tools_call(&cx, 1, params, &budget, SessionState::new(), None);

        assert!(result.is_ok());
        let call_result = result.unwrap();
        assert!(!call_result.is_error);
    }
}

// ============================================================================
// Session Tests
// ============================================================================

#[cfg(test)]
mod session_tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new(
            ServerInfo {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
            ServerCapabilities::default(),
        );

        assert!(!session.is_initialized());
        assert!(session.client_info().is_none());
        assert!(session.client_capabilities().is_none());
        assert!(session.protocol_version().is_none());
    }

    #[test]
    fn test_session_initialization() {
        let mut session = Session::new(
            ServerInfo {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
            ServerCapabilities::default(),
        );

        session.initialize(
            ClientInfo {
                name: "client".to_string(),
                version: "2.0".to_string(),
            },
            ClientCapabilities::default(),
            "2024-11-05".to_string(),
        );

        assert!(session.is_initialized());
        assert_eq!(session.client_info().unwrap().name, "client");
        assert_eq!(session.protocol_version(), Some("2024-11-05"));
    }
}

// ============================================================================
// Cancellation Tests
// ============================================================================

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    #[test]
    fn test_tool_observes_cancellation() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx.clone(), 1);

        // Initially not cancelled
        assert!(!ctx.is_cancelled());

        // Set cancellation
        cx.set_cancel_requested(true);

        // Now tool should observe cancellation
        assert!(ctx.is_cancelled());
    }

    #[test]
    fn test_checkpoint_fails_when_cancelled() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx.clone(), 1);

        // Checkpoint succeeds initially
        assert!(ctx.checkpoint().is_ok());

        // Set cancellation
        cx.set_cancel_requested(true);

        // Checkpoint now fails
        assert!(ctx.checkpoint().is_err());
    }

    #[test]
    fn test_masked_section_defers_cancellation() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx.clone(), 1);

        cx.set_cancel_requested(true);

        // Inside masked section, checkpoint should succeed
        ctx.masked(|| {
            assert!(ctx.checkpoint().is_ok());
        });

        // Outside masked section, checkpoint should fail
        assert!(ctx.checkpoint().is_err());
    }
}

// ============================================================================
// Budget Tests
// ============================================================================

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn test_infinite_budget_not_exhausted() {
        let budget = Budget::INFINITE;
        assert!(!budget.is_exhausted());
    }

    #[test]
    fn test_exhausted_budget() {
        let budget = Budget::unlimited().with_poll_quota(0);
        assert!(budget.is_exhausted());
    }

    #[test]
    fn test_deadline_budget() {
        // A budget with a deadline far in the future
        let budget = Budget::with_deadline_secs(3600);
        assert!(!budget.is_exhausted());
    }
}

// ============================================================================
// Handler Definition Tests
// ============================================================================

#[cfg(test)]
mod handler_definition_tests {
    use super::*;

    #[test]
    fn test_tool_definition() {
        let tool = GreetTool;
        let def = tool.definition();

        assert_eq!(def.name, "greet");
        assert!(def.description.is_some());
        assert!(def.input_schema["type"] == "object");
    }

    #[test]
    fn test_resource_definition() {
        let resource = StaticResource {
            uri: "resource://foo".to_string(),
            content: "bar".to_string(),
        };
        let def = resource.definition();

        assert_eq!(def.uri, "resource://foo");
        assert_eq!(def.mime_type, Some("text/plain".to_string()));
    }

    #[test]
    fn test_prompt_definition() {
        let prompt = GreetingPrompt;
        let def = prompt.definition();

        assert_eq!(def.name, "greeting");
        assert!(!def.arguments.is_empty());
        assert_eq!(def.arguments.len(), 1);
    }
}

// ============================================================================
// Multiple Handler Tests
// ============================================================================

#[cfg(test)]
mod multi_handler_tests {
    use super::*;

    /// Second greeting tool with different behavior.
    struct FormalGreetTool;

    impl ToolHandler for FormalGreetTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "formal_greet".to_string(),
                description: Some("Formally greets a user".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"}
                    }
                }),
            }
        }

        fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
            let name = arguments
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Sir/Madam");
            Ok(vec![Content::Text {
                text: format!("Good day, {name}."),
            }])
        }
    }

    #[test]
    fn test_multiple_tools() {
        let mut router = Router::new();
        router.add_tool(GreetTool);
        router.add_tool(FormalGreetTool);

        let tools = router.tools();
        assert_eq!(tools.len(), 2);

        // Call both tools
        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let result1 = router.handle_tools_call(
            &cx,
            1,
            CallToolParams {
                name: "greet".to_string(),
                arguments: Some(serde_json::json!({"name": "Alice"})),
                meta: None,
            },
            &budget,
            SessionState::new(),
            None,
        );
        assert!(result1.is_ok());

        let result2 = router.handle_tools_call(
            &cx,
            2,
            CallToolParams {
                name: "formal_greet".to_string(),
                arguments: Some(serde_json::json!({"name": "Alice"})),
                meta: None,
            },
            &budget,
            SessionState::new(),
            None,
        );
        assert!(result2.is_ok());

        // Verify different outputs
        if let Content::Text { text: text1 } = &result1.unwrap().content[0] {
            if let Content::Text { text: text2 } = &result2.unwrap().content[0] {
                assert_eq!(text1, "Hello, Alice!");
                assert_eq!(text2, "Good day, Alice.");
            }
        }
    }

    #[test]
    fn test_multiple_resources() {
        let mut router = Router::new();
        router.add_resource(StaticResource {
            uri: "resource://a".to_string(),
            content: "Content A".to_string(),
        });
        router.add_resource(StaticResource {
            uri: "resource://b".to_string(),
            content: "Content B".to_string(),
        });

        let resources = router.resources();
        assert_eq!(resources.len(), 2);

        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        let result_a = router.handle_resources_read(
            &cx,
            1,
            &ReadResourceParams {
                uri: "resource://a".to_string(),
                meta: None,
            },
            &budget,
            SessionState::new(),
            None,
        );
        let result_b = router.handle_resources_read(
            &cx,
            2,
            &ReadResourceParams {
                uri: "resource://b".to_string(),
                meta: None,
            },
            &budget,
            SessionState::new(),
            None,
        );

        assert_eq!(
            result_a.unwrap().contents[0].text,
            Some("Content A".to_string())
        );
        assert_eq!(
            result_b.unwrap().contents[0].text,
            Some("Content B".to_string())
        );
    }
}

// ============================================================================
// Session State Tests
// ============================================================================

mod session_state_tests {
    use super::*;

    /// Tool that increments a counter in session state.
    struct CounterTool;

    impl ToolHandler for CounterTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "increment".to_string(),
                description: Some("Increments a counter in session state".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
            }
        }

        fn call(&self, ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
            let count: i32 = ctx.get_state("counter").unwrap_or(0);
            let new_count = count + 1;
            ctx.set_state("counter", new_count);
            Ok(vec![Content::Text {
                text: format!("Counter: {new_count}"),
            }])
        }
    }

    #[test]
    fn test_session_state_persists_across_calls() {
        let mut router = Router::new();
        router.add_tool(CounterTool);

        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        // Create a shared session state
        let state = SessionState::new();

        // First call - counter should be 1
        let params = CallToolParams {
            name: "increment".to_string(),
            arguments: None,
            meta: None,
        };
        let result1 =
            router.handle_tools_call(&cx, 1, params.clone(), &budget, state.clone(), None);
        assert!(result1.is_ok());
        if let Content::Text { text } = &result1.unwrap().content[0] {
            assert_eq!(text, "Counter: 1");
        }

        // Second call with same state - counter should be 2
        let result2 =
            router.handle_tools_call(&cx, 2, params.clone(), &budget, state.clone(), None);
        assert!(result2.is_ok());
        if let Content::Text { text } = &result2.unwrap().content[0] {
            assert_eq!(text, "Counter: 2");
        }

        // Third call - counter should be 3
        let result3 = router.handle_tools_call(&cx, 3, params, &budget, state.clone(), None);
        assert!(result3.is_ok());
        if let Content::Text { text } = &result3.unwrap().content[0] {
            assert_eq!(text, "Counter: 3");
        }
    }

    #[test]
    fn test_different_session_states_are_independent() {
        let mut router = Router::new();
        router.add_tool(CounterTool);

        let cx = Cx::for_testing();
        let budget = Budget::INFINITE;

        // Create two separate session states
        let state1 = SessionState::new();
        let state2 = SessionState::new();

        let params = CallToolParams {
            name: "increment".to_string(),
            arguments: None,
            meta: None,
        };

        // Call with state1 twice
        router
            .handle_tools_call(&cx, 1, params.clone(), &budget, state1.clone(), None)
            .unwrap();
        let result1 = router
            .handle_tools_call(&cx, 2, params.clone(), &budget, state1.clone(), None)
            .unwrap();

        // Call with state2 once
        let result2 = router
            .handle_tools_call(&cx, 3, params, &budget, state2.clone(), None)
            .unwrap();

        // state1 should have counter=2, state2 should have counter=1
        if let Content::Text { text } = &result1.content[0] {
            assert_eq!(text, "Counter: 2");
        }
        if let Content::Text { text } = &result2.content[0] {
            assert_eq!(text, "Counter: 1");
        }
    }
}

// ============================================================================
// Console Config Integration Tests
// ============================================================================

mod console_config_tests {
    use crate::{BannerStyle, ConsoleConfig, Server, TrafficVerbosity};

    #[test]
    fn test_server_default_console_config() {
        let server = Server::new("test", "1.0.0").build();
        let config = server.console_config();

        // Default config should show banner
        assert!(config.show_banner);
        assert_eq!(config.banner_style, BannerStyle::Full);
    }

    #[test]
    fn test_server_with_console_config() {
        let config = ConsoleConfig::new()
            .with_banner(BannerStyle::Compact)
            .plain_mode();

        let server = Server::new("test", "1.0.0")
            .with_console_config(config)
            .build();

        assert_eq!(server.console_config().banner_style, BannerStyle::Compact);
        assert!(server.console_config().force_plain);
    }

    #[test]
    fn test_server_without_banner() {
        let server = Server::new("test", "1.0.0").without_banner().build();

        assert!(!server.console_config().show_banner);
        assert_eq!(server.console_config().banner_style, BannerStyle::None);
    }

    #[test]
    fn test_server_with_banner_style() {
        let server = Server::new("test", "1.0.0")
            .with_banner(BannerStyle::Minimal)
            .build();

        assert!(server.console_config().show_banner);
        assert_eq!(server.console_config().banner_style, BannerStyle::Minimal);
    }

    #[test]
    fn test_server_with_traffic_logging() {
        let server = Server::new("test", "1.0.0")
            .with_traffic_logging(TrafficVerbosity::Summary)
            .build();

        assert!(server.console_config().show_request_traffic);
        assert_eq!(
            server.console_config().traffic_verbosity,
            TrafficVerbosity::Summary
        );
    }

    #[test]
    fn test_server_with_periodic_stats() {
        let server = Server::new("test", "1.0.0").with_periodic_stats(30).build();

        assert!(server.console_config().show_stats_periodic);
        assert_eq!(server.console_config().stats_interval_secs, 30);
    }

    #[test]
    fn test_server_plain_mode() {
        let server = Server::new("test", "1.0.0").plain_mode().build();

        assert!(server.console_config().force_plain);
    }

    #[test]
    fn test_server_force_color() {
        let server = Server::new("test", "1.0.0").force_color().build();

        assert_eq!(server.console_config().force_color, Some(true));
    }

    #[test]
    fn test_console_config_chaining() {
        let server = Server::new("test", "1.0.0")
            .with_banner(BannerStyle::Compact)
            .with_traffic_logging(TrafficVerbosity::Headers)
            .with_periodic_stats(60)
            .plain_mode()
            .build();

        let config = server.console_config();
        assert_eq!(config.banner_style, BannerStyle::Compact);
        assert_eq!(config.traffic_verbosity, TrafficVerbosity::Headers);
        assert!(config.show_stats_periodic);
        assert_eq!(config.stats_interval_secs, 60);
        assert!(config.force_plain);
    }
}

/// Tests for lifecycle hooks (on_startup, on_shutdown).
mod lifespan_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_on_startup_hook_builder() {
        let startup_called = Arc::new(AtomicBool::new(false));
        let startup_called_clone = startup_called.clone();

        let server = Server::new("test", "1.0.0")
            .on_startup(move || {
                startup_called_clone.store(true, Ordering::SeqCst);
                Ok::<(), std::io::Error>(())
            })
            .build();

        // The hook is stored but not called until run
        // Verify that the lifespan is stored (we can't call run_startup_hook directly
        // since it's private, but we verify the builder works)
        assert!(!startup_called.load(Ordering::SeqCst));

        // Manually trigger the startup hook via the public interface
        // (In production, this would be called by run_loop)
        let startup_success = server.run_startup_hook();
        assert!(startup_success);
        assert!(startup_called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_on_shutdown_hook_builder() {
        let shutdown_called = Arc::new(AtomicBool::new(false));
        let shutdown_called_clone = shutdown_called.clone();

        let server = Server::new("test", "1.0.0")
            .on_shutdown(move || {
                shutdown_called_clone.store(true, Ordering::SeqCst);
            })
            .build();

        // The hook is stored but not called until shutdown
        assert!(!shutdown_called.load(Ordering::SeqCst));

        // Manually trigger the shutdown hook
        server.run_shutdown_hook();
        assert!(shutdown_called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_startup_hook_failure() {
        let server = Server::new("test", "1.0.0")
            .on_startup(|| Err(std::io::Error::other("startup failed")))
            .build();

        // Startup should return false on failure
        let startup_success = server.run_startup_hook();
        assert!(!startup_success);
    }

    #[test]
    fn test_no_hooks_is_ok() {
        let server = Server::new("test", "1.0.0").build();

        // No hooks configured should be fine
        let startup_success = server.run_startup_hook();
        assert!(startup_success);

        // Shutdown hook should also be a no-op
        server.run_shutdown_hook();
    }

    #[test]
    fn test_hooks_only_run_once() {
        let startup_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let startup_count_clone = startup_count.clone();

        let shutdown_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let shutdown_count_clone = shutdown_count.clone();

        let server = Server::new("test", "1.0.0")
            .on_startup(move || {
                startup_count_clone.fetch_add(1, Ordering::SeqCst);
                Ok::<(), std::io::Error>(())
            })
            .on_shutdown(move || {
                shutdown_count_clone.fetch_add(1, Ordering::SeqCst);
            })
            .build();

        // Call startup multiple times
        server.run_startup_hook();
        server.run_startup_hook();
        server.run_startup_hook();

        // Should only have run once (hook is taken)
        assert_eq!(startup_count.load(Ordering::SeqCst), 1);

        // Same for shutdown
        server.run_shutdown_hook();
        server.run_shutdown_hook();
        server.run_shutdown_hook();

        assert_eq!(shutdown_count.load(Ordering::SeqCst), 1);
    }
}
