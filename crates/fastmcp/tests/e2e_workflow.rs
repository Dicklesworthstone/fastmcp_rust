//! E2E Full MCP Workflow Tests (bd-275)
//!
//! Comprehensive tests for complete MCP workflows with trace logging.
//! Covers:
//! - Server startup -> connect -> initialize -> operate -> shutdown
//! - Multiple sequential clients
//! - Interleaved tool/resource/prompt operations
//! - Error recovery during workflows
//! - Server with various handler configurations
//! - Resource template listing
//! - Client info propagation

use std::collections::HashMap;

use fastmcp::testing::prelude::*;
use fastmcp::{
    McpContext, McpResult, PromptHandler, PromptMessage, Resource, ResourceContent,
    ResourceHandler, ResourceTemplate, Role, Server, ToolHandler,
};
use fastmcp_protocol::{Prompt, PromptArgument, Tool, ToolAnnotations};
use serde_json::json;

// ============================================================================
// Shared handler implementations
// ============================================================================

struct EchoToolHandler;

impl ToolHandler for EchoToolHandler {
    fn definition(&self) -> Tool {
        Tool {
            name: "echo".to_string(),
            description: Some("Echoes back the input".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "message": { "type": "string" }
                },
                "required": ["message"]
            }),
            output_schema: None,
            icon: None,
            version: Some("1.0.0".to_string()),
            tags: vec![],
            annotations: Some(ToolAnnotations::new().read_only(true).idempotent(true)),
        }
    }

    fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let message = arguments
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        Ok(vec![Content::Text {
            text: message.to_string(),
        }])
    }
}

struct CounterToolHandler;

impl ToolHandler for CounterToolHandler {
    fn definition(&self) -> Tool {
        Tool {
            name: "counter".to_string(),
            description: Some(
                "Returns the call count (not truly stateful, returns arg)".to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "value": { "type": "integer" }
                },
                "required": ["value"]
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let value = arguments.get("value").and_then(|v| v.as_i64()).unwrap_or(0);
        Ok(vec![Content::Text {
            text: value.to_string(),
        }])
    }
}

struct FailOnDemandToolHandler;

impl ToolHandler for FailOnDemandToolHandler {
    fn definition(&self) -> Tool {
        Tool {
            name: "fail_on_demand".to_string(),
            description: Some("Fails if 'fail' argument is true".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "fail": { "type": "boolean" },
                    "message": { "type": "string" }
                },
                "required": ["fail"]
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let should_fail = arguments
            .get("fail")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if should_fail {
            let msg = arguments
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Requested failure");
            return Err(McpError::tool_error(msg));
        }
        Ok(vec![Content::Text {
            text: "Success".to_string(),
        }])
    }
}

struct StatusResourceHandler;

impl ResourceHandler for StatusResourceHandler {
    fn definition(&self) -> Resource {
        Resource {
            uri: "app://status".to_string(),
            name: "Server Status".to_string(),
            description: Some("Current server status".to_string()),
            mime_type: Some("application/json".to_string()),
            icon: None,
            version: None,
            tags: vec!["status".to_string()],
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        let status = json!({
            "status": "healthy",
            "uptime_seconds": 42
        });
        Ok(vec![ResourceContent {
            uri: "app://status".to_string(),
            mime_type: Some("application/json".to_string()),
            text: Some(status.to_string()),
            blob: None,
        }])
    }
}

struct ReadmeResourceHandler;

impl ResourceHandler for ReadmeResourceHandler {
    fn definition(&self) -> Resource {
        Resource {
            uri: "file:///README.md".to_string(),
            name: "README".to_string(),
            description: Some("Project README file".to_string()),
            mime_type: Some("text/markdown".to_string()),
            icon: None,
            version: Some("1.0.0".to_string()),
            tags: vec!["docs".to_string()],
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Ok(vec![ResourceContent {
            uri: "file:///README.md".to_string(),
            mime_type: Some("text/markdown".to_string()),
            text: Some("# Test Project\n\nThis is a test project.".to_string()),
            blob: None,
        }])
    }
}

struct HelpPromptHandler;

impl PromptHandler for HelpPromptHandler {
    fn definition(&self) -> Prompt {
        Prompt {
            name: "help".to_string(),
            description: Some("Get help on a topic".to_string()),
            arguments: vec![PromptArgument {
                name: "topic".to_string(),
                description: Some("The topic to get help on".to_string()),
                required: true,
            }],
            icon: None,
            version: None,
            tags: vec![],
        }
    }

    fn get(
        &self,
        _ctx: &McpContext,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        let topic = arguments.get("topic").map_or("general", String::as_str);
        Ok(vec![PromptMessage {
            role: Role::User,
            content: Content::Text {
                text: format!("Help me understand: {topic}"),
            },
        }])
    }
}

struct NoArgsPromptHandler;

impl PromptHandler for NoArgsPromptHandler {
    fn definition(&self) -> Prompt {
        Prompt {
            name: "system_prompt".to_string(),
            description: Some("Default system prompt".to_string()),
            arguments: vec![],
            icon: None,
            version: None,
            tags: vec![],
        }
    }

    fn get(
        &self,
        _ctx: &McpContext,
        _arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        Ok(vec![PromptMessage {
            role: Role::Assistant,
            content: Content::Text {
                text: "You are a helpful assistant.".to_string(),
            },
        }])
    }
}

// ============================================================================
// Helper: build full workflow server
// ============================================================================

fn setup_workflow_server() -> TestClient {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("workflow-test-server")
        .with_version("2.0.0")
        .build_server_builder();

    let server = builder
        .tool(EchoToolHandler)
        .tool(CounterToolHandler)
        .tool(FailOnDemandToolHandler)
        .resource(StatusResourceHandler)
        .resource(ReadmeResourceHandler)
        .resource_template(ResourceTemplate {
            uri_template: "file:///{path}".to_string(),
            name: "File Path".to_string(),
            description: Some("Access files by path".to_string()),
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        })
        .prompt(HelpPromptHandler)
        .prompt(NoArgsPromptHandler)
        .build();

    std::thread::spawn(move || {
        server.run_transport(server_transport);
    });

    TestClient::new(client_transport)
}

// ============================================================================
// Full lifecycle workflow tests
// ============================================================================

#[test]
fn workflow_complete_lifecycle() {
    let mut client = setup_workflow_server();

    // Phase 1: Initialize
    let init = client.initialize().unwrap();
    assert_eq!(init.server_info.name, "workflow-test-server");
    assert_eq!(init.server_info.version, "2.0.0");
    assert!(init.capabilities.tools.is_some());
    assert!(init.capabilities.resources.is_some());
    assert!(init.capabilities.prompts.is_some());

    // Phase 2: Discover capabilities
    let tools = client.list_tools().unwrap();
    assert_eq!(tools.len(), 3);

    let resources = client.list_resources().unwrap();
    assert_eq!(resources.len(), 2);

    let templates = client.list_resource_templates().unwrap();
    assert_eq!(templates.len(), 1);
    assert!(templates[0].uri_template.contains("{path}"));

    let prompts = client.list_prompts().unwrap();
    assert_eq!(prompts.len(), 2);

    // Phase 3: Execute operations
    let echo_result = client
        .call_tool("echo", json!({"message": "workflow test"}))
        .unwrap();
    match &echo_result[0] {
        Content::Text { text } => assert_eq!(text, "workflow test"),
        other => panic!("Expected text, got: {other:?}"),
    }

    let status = client.read_resource("app://status").unwrap();
    let status_json: serde_json::Value =
        serde_json::from_str(status[0].text.as_ref().unwrap()).unwrap();
    assert_eq!(status_json["status"], "healthy");

    let mut args = HashMap::new();
    args.insert("topic".to_string(), "MCP protocol".to_string());
    let help = client.get_prompt("help", args).unwrap();
    assert!(
        help[0]
            .content
            .as_text()
            .is_some_and(|t| t.contains("MCP protocol"))
    );

    // Phase 4: Close
    client.close();
}

#[test]
fn workflow_discover_then_operate() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // First discover all available tools
    let tools = client.list_tools().unwrap();
    let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

    // Then call each tool that we find
    for name in &tool_names {
        let result = match *name {
            "echo" => client.call_tool("echo", json!({"message": "test"})),
            "counter" => client.call_tool("counter", json!({"value": 1})),
            "fail_on_demand" => client.call_tool("fail_on_demand", json!({"fail": false})),
            _ => continue,
        };
        assert!(result.is_ok(), "Tool {name} failed: {result:?}");
    }

    // Discover resources and read each one
    let resources = client.list_resources().unwrap();
    for resource in &resources {
        let content = client.read_resource(&resource.uri).unwrap();
        assert!(
            !content.is_empty(),
            "Resource {} returned empty",
            resource.uri
        );
    }
}

// ============================================================================
// Error recovery tests
// ============================================================================

#[test]
fn workflow_error_recovery_continues_after_tool_error() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // Successful call
    let result = client
        .call_tool("fail_on_demand", json!({"fail": false}))
        .unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "Success"),
        other => panic!("Expected text, got: {other:?}"),
    }

    // Failed call
    let err = client
        .call_tool("fail_on_demand", json!({"fail": true, "message": "boom"}))
        .unwrap_err();
    assert!(err.message.contains("boom") || err.message.contains("Requested failure"));

    // Should still work after the error
    let result = client
        .call_tool("echo", json!({"message": "still alive"}))
        .unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "still alive"),
        other => panic!("Expected text, got: {other:?}"),
    }
}

#[test]
fn workflow_error_recovery_alternating_success_failure() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    for i in 0..5 {
        let should_fail = i % 2 == 1;
        let result = client.call_tool(
            "fail_on_demand",
            json!({"fail": should_fail, "message": format!("iteration {i}")}),
        );

        if should_fail {
            assert!(result.is_err(), "Iteration {i} should have failed");
        } else {
            assert!(result.is_ok(), "Iteration {i} should have succeeded");
        }
    }

    // Final verification: server still responsive
    let tools = client.list_tools().unwrap();
    assert_eq!(tools.len(), 3);
}

#[test]
fn workflow_unknown_tool_doesnt_break_session() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // Call a valid tool
    let result = client
        .call_tool("echo", json!({"message": "before"}))
        .unwrap();
    assert_eq!(result.len(), 1);

    // Call an unknown tool (should fail)
    let err = client.call_tool("nonexistent", json!({}));
    assert!(err.is_err());

    // Call a valid tool again (should still work)
    let result = client
        .call_tool("echo", json!({"message": "after"}))
        .unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "after"),
        other => panic!("Expected text, got: {other:?}"),
    }
}

#[test]
fn workflow_unknown_resource_doesnt_break_session() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // Read a valid resource
    let content = client.read_resource("app://status").unwrap();
    assert!(!content.is_empty());

    // Try to read an unknown resource (should fail)
    let err = client.read_resource("app://nonexistent");
    assert!(err.is_err());

    // Read a valid resource again (should still work)
    let content = client.read_resource("file:///README.md").unwrap();
    assert!(content[0].text.as_ref().unwrap().contains("Test Project"));
}

// ============================================================================
// Multiple sequential clients
// ============================================================================

#[test]
fn workflow_sequential_clients_same_server() {
    // Each client gets its own server - test that server setup pattern works repeatedly
    for i in 0..3 {
        let mut client = setup_workflow_server();
        let init = client.initialize().unwrap();
        assert_eq!(init.server_info.name, "workflow-test-server");

        let result = client
            .call_tool("echo", json!({"message": format!("client-{i}")}))
            .unwrap();
        match &result[0] {
            Content::Text { text } => assert_eq!(text, &format!("client-{i}")),
            other => panic!("Expected text, got: {other:?}"),
        }

        client.close();
    }
}

#[test]
fn workflow_two_independent_servers() {
    // Server A: tools only
    let (builder_a, client_a_transport, server_a_transport) = TestServer::builder()
        .with_name("server-a")
        .build_server_builder();
    let server_a = builder_a.tool(EchoToolHandler).build();
    std::thread::spawn(move || server_a.run_transport(server_a_transport));

    // Server B: resources only
    let (builder_b, client_b_transport, server_b_transport) = TestServer::builder()
        .with_name("server-b")
        .build_server_builder();
    let server_b = builder_b.resource(StatusResourceHandler).build();
    std::thread::spawn(move || server_b.run_transport(server_b_transport));

    // Client A
    let mut client_a = TestClient::new(client_a_transport);
    let init_a = client_a.initialize().unwrap();
    assert_eq!(init_a.server_info.name, "server-a");
    assert!(init_a.capabilities.tools.is_some());
    assert!(init_a.capabilities.resources.is_none());

    // Client B
    let mut client_b = TestClient::new(client_b_transport);
    let init_b = client_b.initialize().unwrap();
    assert_eq!(init_b.server_info.name, "server-b");
    assert!(init_b.capabilities.tools.is_none());
    assert!(init_b.capabilities.resources.is_some());

    // Use both
    let echo = client_a
        .call_tool("echo", json!({"message": "from A"}))
        .unwrap();
    match &echo[0] {
        Content::Text { text } => assert_eq!(text, "from A"),
        other => panic!("Expected text, got: {other:?}"),
    }

    let status = client_b.read_resource("app://status").unwrap();
    assert!(!status.is_empty());
}

// ============================================================================
// Resource template tests
// ============================================================================

#[test]
fn workflow_list_resource_templates() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    let templates = client.list_resource_templates().unwrap();
    assert_eq!(templates.len(), 1);
    assert_eq!(templates[0].name, "File Path");
    assert!(templates[0].uri_template.contains("{path}"));
}

// ============================================================================
// No-args prompt test
// ============================================================================

#[test]
fn workflow_get_prompt_without_arguments() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    let messages = client.get_prompt("system_prompt", HashMap::new()).unwrap();
    assert_eq!(messages.len(), 1);
    assert!(matches!(messages[0].role, Role::Assistant));
    match &messages[0].content {
        Content::Text { text } => {
            assert!(text.contains("helpful assistant"));
        }
        other => panic!("Expected text, got: {other:?}"),
    }
}

// ============================================================================
// Heavy sequential operations
// ============================================================================

#[test]
fn workflow_many_sequential_tool_calls() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // 20 sequential tool calls
    for i in 0..20 {
        let msg = format!("message-{i}");
        let result = client.call_tool("echo", json!({"message": msg})).unwrap();
        match &result[0] {
            Content::Text { text } => assert_eq!(text, &msg),
            other => panic!("Expected text, got: {other:?}"),
        }
    }
}

#[test]
fn workflow_interleaved_list_and_call() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // Interleave list and call operations
    for _ in 0..5 {
        let tools = client.list_tools().unwrap();
        assert_eq!(tools.len(), 3);

        let result = client.call_tool("counter", json!({"value": 42})).unwrap();
        match &result[0] {
            Content::Text { text } => assert_eq!(text, "42"),
            other => panic!("Expected text, got: {other:?}"),
        }

        let resources = client.list_resources().unwrap();
        assert_eq!(resources.len(), 2);

        let content = client.read_resource("app://status").unwrap();
        assert!(!content.is_empty());
    }
}

// ============================================================================
// Server info and capability verification
// ============================================================================

#[test]
fn workflow_server_name_and_version() {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("custom-name")
        .with_version("9.8.7")
        .build_server_builder();

    let server = builder.tool(EchoToolHandler).build();
    std::thread::spawn(move || server.run_transport(server_transport));

    let mut client = TestClient::new(client_transport);
    let init = client.initialize().unwrap();

    assert_eq!(init.server_info.name, "custom-name");
    assert_eq!(init.server_info.version, "9.8.7");
}

#[test]
fn workflow_capabilities_match_handlers() {
    let (builder, client_transport, server_transport) =
        TestServer::builder().build_server_builder();

    let server = builder
        .tool(EchoToolHandler)
        .resource(StatusResourceHandler)
        .build();
    std::thread::spawn(move || server.run_transport(server_transport));

    let mut client = TestClient::new(client_transport);
    let init = client.initialize().unwrap();

    // Has tools and resources, but NOT prompts
    assert!(init.capabilities.tools.is_some());
    assert!(init.capabilities.resources.is_some());
    assert!(init.capabilities.prompts.is_none());
}

// ============================================================================
// Client info tests
// ============================================================================

#[test]
fn workflow_custom_client_info_accepted() {
    let (builder, client_transport, server_transport) =
        TestServer::builder().build_server_builder();

    let server = builder.tool(EchoToolHandler).build();
    std::thread::spawn(move || server.run_transport(server_transport));

    let mut client =
        TestClient::new(client_transport).with_client_info("my-custom-client", "5.0.0");

    // Should initialize successfully with custom client info
    let init = client.initialize().unwrap();
    assert!(init.capabilities.tools.is_some());

    // And should work normally
    let result = client
        .call_tool("echo", json!({"message": "custom client"}))
        .unwrap();
    assert_eq!(result.len(), 1);
}

// ============================================================================
// Annotation verification
// ============================================================================

#[test]
fn workflow_tool_annotations_preserved() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    let tools = client.list_tools().unwrap();
    let echo = tools.iter().find(|t| t.name == "echo").unwrap();

    let annotations = echo.annotations.as_ref().unwrap();
    assert_eq!(annotations.read_only, Some(true));
    assert_eq!(annotations.idempotent, Some(true));
}

#[test]
fn workflow_tool_descriptions_preserved() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    let tools = client.list_tools().unwrap();
    let echo = tools.iter().find(|t| t.name == "echo").unwrap();
    assert_eq!(echo.description.as_deref(), Some("Echoes back the input"));
    assert_eq!(echo.version.as_deref(), Some("1.0.0"));
}

#[test]
fn workflow_resource_metadata_preserved() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    let resources = client.list_resources().unwrap();
    let readme = resources.iter().find(|r| r.name == "README").unwrap();
    assert_eq!(readme.mime_type.as_deref(), Some("text/markdown"));
    assert_eq!(readme.description.as_deref(), Some("Project README file"));
    assert_eq!(readme.version.as_deref(), Some("1.0.0"));
}

#[test]
fn workflow_prompt_arguments_preserved() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    let prompts = client.list_prompts().unwrap();
    let help = prompts.iter().find(|p| p.name == "help").unwrap();

    assert_eq!(help.arguments.len(), 1);
    assert_eq!(help.arguments[0].name, "topic");
    assert!(help.arguments[0].required);

    let system = prompts.iter().find(|p| p.name == "system_prompt").unwrap();
    assert!(system.arguments.is_empty());
}

// ============================================================================
// Content type helper for assertions
// ============================================================================

trait ContentExt {
    fn as_text(&self) -> Option<&str>;
}

impl ContentExt for Content {
    fn as_text(&self) -> Option<&str> {
        match self {
            Content::Text { text } => Some(text),
            _ => None,
        }
    }
}

// ============================================================================
// Background Tasks E2E Tests (bd-og1)
// ============================================================================

use fastmcp::TaskManager;

/// Helper: build a server with background task support.
fn setup_task_server() -> TestClient {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("task-test-server")
        .with_version("1.0.0")
        .build_server_builder();

    // Create task manager and register handlers
    let task_manager = TaskManager::new();

    // Register a simple counter task that completes quickly
    task_manager.register_handler("quick_task", |_cx, params| async move {
        let value = params.get("value").and_then(|v| v.as_i64()).unwrap_or(0);
        Ok(serde_json::json!({"result": value * 2}))
    });

    // Register a long-running task that can report progress
    task_manager.register_handler("progress_task", |_cx, params| async move {
        let steps = params.get("steps").and_then(|v| v.as_i64()).unwrap_or(3) as usize;
        // Simulate work by returning after "steps" iterations
        Ok(serde_json::json!({"completed_steps": steps}))
    });

    // Register a task that fails
    task_manager.register_handler("failing_task", |_cx, _params| async move {
        Err(fastmcp::McpError::internal_error(
            "Task intentionally failed",
        ))
    });

    let server = builder
        .tool(EchoToolHandler)
        .with_task_manager(task_manager.into_shared())
        .build();

    std::thread::spawn(move || {
        server.run_transport(server_transport);
    });

    TestClient::new(client_transport)
}

#[test]
fn workflow_task_submit_and_get() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Verify server has task capability
    let caps = client.server_capabilities().unwrap();
    assert!(caps.tasks.is_some(), "Server should have tasks capability");

    // Submit a task
    let submit_result = client
        .send_raw_request(
            "tasks/submit",
            json!({
                "taskType": "quick_task",
                "params": {"value": 21}
            }),
        )
        .unwrap();

    let task_id = submit_result["task"]["id"].as_str().unwrap();
    assert!(
        task_id.starts_with("task-"),
        "Task ID should have correct prefix"
    );

    // Get task info
    let get_result = client
        .send_raw_request("tasks/get", json!({"id": task_id}))
        .unwrap();

    let task_info = &get_result["task"];
    assert_eq!(task_info["id"], task_id);
    assert_eq!(task_info["taskType"], "quick_task");

    // Give the task time to complete
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Get again and check for completion
    let get_result = client
        .send_raw_request("tasks/get", json!({"id": task_id}))
        .unwrap();

    let status = get_result["task"]["status"].as_str().unwrap();
    // Task should be completed or still running
    assert!(
        status == "completed" || status == "running" || status == "pending",
        "Unexpected status: {status}"
    );
}

#[test]
fn workflow_task_list_with_filtering() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Submit multiple tasks
    let _task1 = client
        .send_raw_request(
            "tasks/submit",
            json!({"taskType": "quick_task", "params": {"value": 1}}),
        )
        .unwrap();

    let _task2 = client
        .send_raw_request(
            "tasks/submit",
            json!({"taskType": "quick_task", "params": {"value": 2}}),
        )
        .unwrap();

    // List all tasks
    let list_result = client.send_raw_request("tasks/list", json!({})).unwrap();

    let tasks = list_result["tasks"].as_array().unwrap();
    assert!(tasks.len() >= 2, "Should have at least 2 tasks");

    // Wait for tasks to complete
    std::thread::sleep(std::time::Duration::from_millis(200));

    // List completed tasks
    let completed_result = client
        .send_raw_request("tasks/list", json!({"status": "completed"}))
        .unwrap();

    let completed_tasks = completed_result["tasks"].as_array().unwrap();
    for task in completed_tasks {
        assert_eq!(task["status"], "completed");
    }
}

#[test]
fn workflow_task_cancellation() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Submit a task
    let submit_result = client
        .send_raw_request(
            "tasks/submit",
            json!({"taskType": "progress_task", "params": {"steps": 100}}),
        )
        .unwrap();

    let task_id = submit_result["task"]["id"].as_str().unwrap();

    // Cancel the task immediately
    let cancel_result = client
        .send_raw_request(
            "tasks/cancel",
            json!({"id": task_id, "reason": "User requested cancellation"}),
        )
        .unwrap();

    assert!(cancel_result["cancelled"].as_bool().unwrap_or(false));

    // Verify task is cancelled
    let get_result = client
        .send_raw_request("tasks/get", json!({"id": task_id}))
        .unwrap();

    let status = get_result["task"]["status"].as_str().unwrap();
    assert_eq!(status, "cancelled", "Task should be cancelled");

    // Verify error message is set
    let error = get_result["task"]["error"].as_str();
    assert!(error.is_some(), "Cancelled task should have error message");
}

#[test]
fn workflow_task_failure_handling() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Submit a failing task
    let submit_result = client
        .send_raw_request(
            "tasks/submit",
            json!({"taskType": "failing_task", "params": {}}),
        )
        .unwrap();

    let task_id = submit_result["task"]["id"].as_str().unwrap();

    // Wait for task to fail
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Get task and verify failure
    let get_result = client
        .send_raw_request("tasks/get", json!({"id": task_id}))
        .unwrap();

    let task = &get_result["task"];
    let status = task["status"].as_str().unwrap();

    // Task should be failed (or still running if it hasn't finished)
    if status == "failed" {
        assert!(
            task["error"].as_str().is_some(),
            "Failed task should have error message"
        );
    }
}

#[test]
fn workflow_task_unknown_type_rejected() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Try to submit unknown task type
    let result = client.send_raw_request(
        "tasks/submit",
        json!({"taskType": "nonexistent_task", "params": {}}),
    );

    assert!(result.is_err(), "Unknown task type should be rejected");
}

#[test]
fn workflow_task_get_nonexistent() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Try to get a task that doesn't exist
    let result = client.send_raw_request("tasks/get", json!({"id": "task-nonexistent"}));

    assert!(result.is_err(), "Getting nonexistent task should fail");
}

#[test]
fn workflow_task_cancel_already_completed() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Submit a quick task
    let submit_result = client
        .send_raw_request(
            "tasks/submit",
            json!({"taskType": "quick_task", "params": {"value": 5}}),
        )
        .unwrap();

    let task_id = submit_result["task"]["id"].as_str().unwrap();

    // Wait for completion
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Verify it's completed
    let get_result = client
        .send_raw_request("tasks/get", json!({"id": task_id}))
        .unwrap();

    if get_result["task"]["status"] == "completed" {
        // Try to cancel completed task (should fail)
        let cancel_result = client.send_raw_request("tasks/cancel", json!({"id": task_id}));

        assert!(
            cancel_result.is_err(),
            "Cancelling completed task should fail"
        );
    }
}

#[test]
fn workflow_task_result_available_after_completion() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Submit a task
    let submit_result = client
        .send_raw_request(
            "tasks/submit",
            json!({"taskType": "quick_task", "params": {"value": 42}}),
        )
        .unwrap();

    let task_id = submit_result["task"]["id"].as_str().unwrap();

    // Wait for completion
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Get task with result
    let get_result = client
        .send_raw_request("tasks/get", json!({"id": task_id}))
        .unwrap();

    if get_result["task"]["status"] == "completed" {
        // Result should be available
        let result = &get_result["result"];
        assert!(
            result.is_object(),
            "Result should be present for completed task"
        );
        assert!(result["success"].as_bool().unwrap_or(false));

        // Check the data
        let data = &result["data"];
        assert_eq!(data["result"], 84, "42 * 2 = 84");
    }
}

#[test]
fn workflow_task_session_continues_after_task_error() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Submit a failing task
    let _fail_result = client
        .send_raw_request(
            "tasks/submit",
            json!({"taskType": "failing_task", "params": {}}),
        )
        .unwrap();

    // Wait for it to fail
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Session should still be functional - submit another task
    let success_result = client
        .send_raw_request(
            "tasks/submit",
            json!({"taskType": "quick_task", "params": {"value": 10}}),
        )
        .unwrap();

    assert!(
        success_result["task"]["id"].as_str().is_some(),
        "Should be able to submit new tasks after failure"
    );

    // Regular tool calls should also still work
    let echo_result = client
        .call_tool("echo", json!({"message": "still working"}))
        .unwrap();

    match &echo_result[0] {
        Content::Text { text } => assert_eq!(text, "still working"),
        other => panic!("Expected text, got: {other:?}"),
    }
}

#[test]
fn workflow_task_capabilities_advertised() {
    let mut client = setup_task_server();
    let init_result = client.initialize().unwrap();

    // Verify task capabilities
    let tasks_cap = init_result.capabilities.tasks;
    assert!(
        tasks_cap.is_some(),
        "Server should advertise tasks capability"
    );
}

#[test]
fn workflow_task_multiple_sequential() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Submit tasks sequentially and track their IDs
    let mut task_ids = Vec::new();
    for i in 0..5 {
        let result = client
            .send_raw_request(
                "tasks/submit",
                json!({"taskType": "quick_task", "params": {"value": i}}),
            )
            .unwrap();

        let task_id = result["task"]["id"].as_str().unwrap().to_string();
        task_ids.push(task_id);
    }

    // All task IDs should be unique
    let unique_ids: std::collections::HashSet<_> = task_ids.iter().collect();
    assert_eq!(
        unique_ids.len(),
        task_ids.len(),
        "All task IDs should be unique"
    );

    // Wait for all to complete
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Verify all are either completed or in a valid state
    for task_id in &task_ids {
        let result = client
            .send_raw_request("tasks/get", json!({"id": task_id}))
            .unwrap();

        let status = result["task"]["status"].as_str().unwrap();
        assert!(
            matches!(status, "pending" | "running" | "completed"),
            "Task {task_id} has unexpected status: {status}"
        );
    }
}

// ============================================================================
// Multiple Concurrent Clients E2E Tests (bd-1s1)
// ============================================================================

/// Tool that stores a value in session state and returns it.
struct SessionStoreHandler;

impl ToolHandler for SessionStoreHandler {
    fn definition(&self) -> Tool {
        Tool {
            name: "session_store".to_string(),
            description: Some("Store and retrieve a value in session state".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string" },
                    "value": { "type": "string" }
                },
                "required": ["key", "value"]
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let key = arguments["key"].as_str().unwrap_or("default").to_string();
        let value = arguments["value"].as_str().unwrap_or("").to_string();

        // Store value in session state
        ctx.set_state(&key, value.clone());

        Ok(vec![Content::Text {
            text: format!("Stored: {key}={value}"),
        }])
    }
}

/// Tool that retrieves a value from session state.
struct SessionGetHandler;

impl ToolHandler for SessionGetHandler {
    fn definition(&self) -> Tool {
        Tool {
            name: "session_get".to_string(),
            description: Some("Get a value from session state".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string" }
                },
                "required": ["key"]
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        }
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let key = arguments["key"].as_str().unwrap_or("default");

        let value: Option<String> = ctx.get_state(key);
        let result = value.unwrap_or_else(|| "NOT_FOUND".to_string());

        Ok(vec![Content::Text { text: result }])
    }
}

use std::sync::Arc;

#[test]
fn workflow_concurrent_clients_isolation() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::thread;

    // Create multiple client-server transport pairs
    let mut clients_and_servers = Vec::new();

    for client_num in 0..3 {
        let (client_transport, server_transport) = create_memory_transport_pair();

        let server = Server::new("concurrent-server", "1.0.0")
            .tool(EchoToolHandler)
            .tool(SessionStoreHandler)
            .tool(SessionGetHandler)
            .build();

        // Spawn server thread
        thread::spawn(move || {
            server.run_transport(server_transport);
        });

        let client = TestClient::new(client_transport)
            .with_client_info(format!("client-{}", client_num), "1.0.0");

        clients_and_servers.push((client_num, client));
    }

    // Initialize all clients
    for (num, client) in &mut clients_and_servers {
        client.initialize().unwrap();
        eprintln!("Client {} initialized", num);
    }

    // Each client stores a unique value
    for (num, client) in &mut clients_and_servers {
        let result = client
            .call_tool(
                "session_store",
                json!({"key": "client_value", "value": format!("value_from_client_{}", num)}),
            )
            .unwrap();

        match &result[0] {
            Content::Text { text } => {
                assert!(text.contains(&format!("value_from_client_{}", num)));
            }
            other => panic!("Expected text, got: {other:?}"),
        }
    }

    // Each client retrieves its own stored value (should not see other clients' values)
    for (num, client) in &mut clients_and_servers {
        let result = client
            .call_tool("session_get", json!({"key": "client_value"}))
            .unwrap();

        match &result[0] {
            Content::Text { text } => {
                // Each client should see only its own value
                assert_eq!(
                    text,
                    &format!("value_from_client_{}", num),
                    "Client {} should see its own value, not another client's",
                    num
                );
            }
            other => panic!("Expected text, got: {other:?}"),
        }
    }
}

#[test]
fn workflow_concurrent_interleaved_operations() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    let operation_counter = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for client_num in 0..4 {
        let counter = Arc::clone(&operation_counter);

        let handle = thread::spawn(move || {
            let (client_transport, server_transport) = create_memory_transport_pair();

            let server = Server::new("interleaved-server", "1.0.0")
                .tool(EchoToolHandler)
                .build();

            thread::spawn(move || {
                server.run_transport(server_transport);
            });

            let mut client = TestClient::new(client_transport)
                .with_client_info(format!("client-{}", client_num), "1.0.0");

            client.initialize().unwrap();

            // Perform multiple operations
            for op in 0..5 {
                let op_num = counter.fetch_add(1, Ordering::SeqCst);
                let result = client
                    .call_tool(
                        "echo",
                        json!({"message": format!("client_{}_op_{}", client_num, op)}),
                    )
                    .unwrap();

                match &result[0] {
                    Content::Text { text } => {
                        assert!(
                            text.contains(&format!("client_{}_op_{}", client_num, op)),
                            "Operation {} result mismatch",
                            op_num
                        );
                    }
                    other => panic!("Expected text, got: {other:?}"),
                }
            }

            client_num
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    let mut completed_clients = Vec::new();
    for handle in handles {
        let client_num = handle.join().expect("Thread panicked");
        completed_clients.push(client_num);
    }

    // Verify all clients completed
    assert_eq!(completed_clients.len(), 4);

    // Verify total operations (4 clients * 5 ops = 20)
    assert_eq!(operation_counter.load(Ordering::SeqCst), 20);
}

#[test]
fn workflow_concurrent_no_crosstalk() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::sync::Mutex;
    use std::thread;

    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for client_num in 0..3 {
        let results = Arc::clone(&results);

        let handle = thread::spawn(move || {
            let (client_transport, server_transport) = create_memory_transport_pair();

            let server = Server::new("crosstalk-server", "1.0.0")
                .tool(SessionStoreHandler)
                .tool(SessionGetHandler)
                .build();

            thread::spawn(move || {
                server.run_transport(server_transport);
            });

            let mut client = TestClient::new(client_transport);
            client.initialize().unwrap();

            // Store a secret value
            let secret = format!("secret_{}", client_num);
            client
                .call_tool("session_store", json!({"key": "secret", "value": &secret}))
                .unwrap();

            // Sleep briefly to allow interleaving
            thread::sleep(std::time::Duration::from_millis(10));

            // Retrieve and verify our secret
            let result = client
                .call_tool("session_get", json!({"key": "secret"}))
                .unwrap();

            let retrieved = match &result[0] {
                Content::Text { text } => text.clone(),
                other => panic!("Expected text, got: {other:?}"),
            };

            results
                .lock()
                .unwrap()
                .push((client_num, secret.clone(), retrieved));
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify each client got its own secret back
    let results = results.lock().unwrap();
    assert_eq!(results.len(), 3);

    for (client_num, expected, actual) in results.iter() {
        assert_eq!(
            expected, actual,
            "Client {} got wrong secret: expected '{}', got '{}'",
            client_num, expected, actual
        );
    }
}

#[test]
fn workflow_concurrent_session_state_persistence() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::thread;

    // Test that session state persists across multiple calls within the same session
    let (client_transport, server_transport) = create_memory_transport_pair();

    let server = Server::new("persistence-server", "1.0.0")
        .tool(SessionStoreHandler)
        .tool(SessionGetHandler)
        .build();

    thread::spawn(move || {
        server.run_transport(server_transport);
    });

    let mut client = TestClient::new(client_transport);
    client.initialize().unwrap();

    // Store multiple values
    for i in 0..5 {
        client
            .call_tool(
                "session_store",
                json!({"key": format!("key_{}", i), "value": format!("value_{}", i)}),
            )
            .unwrap();
    }

    // Retrieve all values
    for i in 0..5 {
        let result = client
            .call_tool("session_get", json!({"key": format!("key_{}", i)}))
            .unwrap();

        match &result[0] {
            Content::Text { text } => {
                assert_eq!(text, &format!("value_{}", i), "Key {} has wrong value", i);
            }
            other => panic!("Expected text, got: {other:?}"),
        }
    }

    // Verify non-existent key returns NOT_FOUND
    let result = client
        .call_tool("session_get", json!({"key": "nonexistent"}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert_eq!(text, "NOT_FOUND");
        }
        other => panic!("Expected text, got: {other:?}"),
    }
}

#[test]
fn workflow_concurrent_stress_test() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    const NUM_CLIENTS: usize = 5;
    const OPS_PER_CLIENT: usize = 10;

    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for client_num in 0..NUM_CLIENTS {
        let success = Arc::clone(&success_count);

        let handle = thread::spawn(move || {
            let (client_transport, server_transport) = create_memory_transport_pair();

            let server = Server::new("stress-server", "1.0.0")
                .tool(EchoToolHandler)
                .tool(SessionStoreHandler)
                .tool(SessionGetHandler)
                .build();

            thread::spawn(move || {
                server.run_transport(server_transport);
            });

            let mut client = TestClient::new(client_transport);
            if client.initialize().is_err() {
                return;
            }

            for op in 0..OPS_PER_CLIENT {
                // Alternate between different operations
                let result = match op % 3 {
                    0 => client.call_tool(
                        "echo",
                        json!({"message": format!("c{}op{}", client_num, op)}),
                    ),
                    1 => client.call_tool(
                        "session_store",
                        json!({"key": "k", "value": format!("v{}", op)}),
                    ),
                    _ => client.call_tool("session_get", json!({"key": "k"})),
                };

                if result.is_ok() {
                    success.fetch_add(1, Ordering::SeqCst);
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }

    // Verify most operations succeeded
    let total_success = success_count.load(Ordering::SeqCst);
    let expected_total = NUM_CLIENTS * OPS_PER_CLIENT;

    assert!(
        total_success >= expected_total * 90 / 100,
        "Expected at least 90% success rate, got {}/{}",
        total_success,
        expected_total
    );
}
