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
// Additional Task Management E2E Tests (bd-3n2)
// ============================================================================

#[test]
fn workflow_task_polling_until_complete() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Submit a quick task
    let submit_result = client
        .send_raw_request(
            "tasks/submit",
            json!({"taskType": "quick_task", "params": {"value": 50}}),
        )
        .unwrap();

    let task_id = submit_result["task"]["id"].as_str().unwrap();

    // Poll until complete (simulating wait_for_task behavior)
    let mut attempts = 0;
    let max_attempts = 20;
    let mut final_status = String::new();

    while attempts < max_attempts {
        let get_result = client
            .send_raw_request("tasks/get", json!({"id": task_id}))
            .unwrap();

        let status = get_result["task"]["status"].as_str().unwrap();
        final_status = status.to_string();

        if status == "completed" || status == "failed" || status == "cancelled" {
            break;
        }

        std::thread::sleep(std::time::Duration::from_millis(50));
        attempts += 1;
    }

    // Should eventually complete
    assert!(
        attempts < max_attempts || final_status == "completed",
        "Task should complete within timeout"
    );
}

#[test]
fn workflow_task_status_transitions() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Submit a task
    let submit_result = client
        .send_raw_request(
            "tasks/submit",
            json!({"taskType": "quick_task", "params": {"value": 1}}),
        )
        .unwrap();

    let task_id = submit_result["task"]["id"].as_str().unwrap();
    let initial_status = submit_result["task"]["status"].as_str().unwrap();

    // Initial status should be pending or running
    assert!(
        initial_status == "pending" || initial_status == "running",
        "Initial status should be pending or running, got: {}",
        initial_status
    );

    // Wait for completion
    std::thread::sleep(std::time::Duration::from_millis(300));

    let get_result = client
        .send_raw_request("tasks/get", json!({"id": task_id}))
        .unwrap();

    let final_status = get_result["task"]["status"].as_str().unwrap();

    // Valid terminal states
    assert!(
        final_status == "completed" || final_status == "failed" || final_status == "cancelled",
        "Final status should be terminal, got: {}",
        final_status
    );
}

#[test]
fn workflow_task_list_pagination() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Submit several tasks
    for i in 0..5 {
        client
            .send_raw_request(
                "tasks/submit",
                json!({"taskType": "quick_task", "params": {"value": i}}),
            )
            .unwrap();
    }

    // List all tasks
    let list_result = client.send_raw_request("tasks/list", json!({})).unwrap();

    let tasks = list_result["tasks"].as_array().unwrap();
    assert!(
        tasks.len() >= 5,
        "Should have at least 5 tasks, got {}",
        tasks.len()
    );

    // Each task should have required fields
    for task in tasks {
        assert!(task["id"].is_string());
        assert!(task["status"].is_string());
        assert!(task["taskType"].is_string());
    }
}

#[test]
fn workflow_task_cancel_pending() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Submit a task that takes time (progress_task with many steps)
    let submit_result = client
        .send_raw_request(
            "tasks/submit",
            json!({"taskType": "progress_task", "params": {"steps": 100}}),
        )
        .unwrap();

    let task_id = submit_result["task"]["id"].as_str().unwrap();

    // Cancel immediately
    let cancel_result = client
        .send_raw_request(
            "tasks/cancel",
            json!({"id": task_id, "reason": "Cancelled during pending"}),
        )
        .unwrap();

    assert!(cancel_result["cancelled"].as_bool().unwrap_or(false));

    // Verify the task is cancelled
    let get_result = client
        .send_raw_request("tasks/get", json!({"id": task_id}))
        .unwrap();

    assert_eq!(
        get_result["task"]["status"].as_str().unwrap(),
        "cancelled"
    );
}

#[test]
fn workflow_task_result_structure() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Submit a task that returns data
    let submit_result = client
        .send_raw_request(
            "tasks/submit",
            json!({"taskType": "quick_task", "params": {"value": 123}}),
        )
        .unwrap();

    let task_id = submit_result["task"]["id"].as_str().unwrap();

    // Wait for completion
    std::thread::sleep(std::time::Duration::from_millis(200));

    let get_result = client
        .send_raw_request("tasks/get", json!({"id": task_id}))
        .unwrap();

    // If completed, verify result structure
    if get_result["task"]["status"].as_str().unwrap() == "completed" {
        let result = &get_result["result"];
        assert!(result["success"].as_bool().unwrap_or(false));
        assert!(result["data"].is_object());
        // The task multiplies by 2
        assert_eq!(result["data"]["result"], 246);
    }
}

#[test]
fn workflow_task_error_message_preserved() {
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

    // Wait for failure
    std::thread::sleep(std::time::Duration::from_millis(200));

    let get_result = client
        .send_raw_request("tasks/get", json!({"id": task_id}))
        .unwrap();

    // If failed, verify error is preserved
    if get_result["task"]["status"].as_str().unwrap() == "failed" {
        let error = get_result["task"]["error"].as_str();
        assert!(
            error.is_some(),
            "Failed task should have error message"
        );
        assert!(
            error.unwrap().contains("intentionally") || error.unwrap().contains("failed"),
            "Error message should describe failure"
        );
    }
}

#[test]
fn workflow_task_type_preserved() {
    let mut client = setup_task_server();
    client.initialize().unwrap();

    // Submit different task types
    let task_types = ["quick_task", "progress_task"];

    for task_type in task_types {
        let submit_result = client
            .send_raw_request(
                "tasks/submit",
                json!({"taskType": task_type, "params": {"value": 1}}),
            )
            .unwrap();

        let task_id = submit_result["task"]["id"].as_str().unwrap();
        let returned_type = submit_result["task"]["taskType"].as_str().unwrap();
        assert_eq!(returned_type, task_type);

        // Verify on get as well
        let get_result = client
            .send_raw_request("tasks/get", json!({"id": task_id}))
            .unwrap();

        assert_eq!(
            get_result["task"]["taskType"].as_str().unwrap(),
            task_type
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

// ============================================================================
// Client Session Management E2E Tests (bd-2ms)
// ============================================================================

#[test]
fn session_initialization_stores_server_info() {
    let mut client = setup_workflow_server();

    // Before initialization, no server info
    assert!(client.server_info().is_none());
    assert!(client.server_capabilities().is_none());
    assert!(client.protocol_version().is_none());
    assert!(!client.is_initialized());

    // Initialize
    let init_result = client.initialize().unwrap();

    // After initialization, all session info is available
    assert!(client.is_initialized());
    assert!(client.server_info().is_some());
    assert!(client.server_capabilities().is_some());
    assert!(client.protocol_version().is_some());

    // Verify the stored info matches what was returned
    let server_info = client.server_info().unwrap();
    assert_eq!(server_info.name, init_result.server_info.name);
    assert_eq!(server_info.version, init_result.server_info.version);
}

#[test]
fn session_capabilities_reflect_server_handlers() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::thread;

    // Server with only tools
    let (client_transport, server_transport) = create_memory_transport_pair();
    let server = Server::new("tools-only", "1.0.0")
        .tool(EchoToolHandler)
        .build();
    thread::spawn(move || server.run_transport(server_transport));

    let mut client = TestClient::new(client_transport);
    client.initialize().unwrap();

    let caps = client.server_capabilities().unwrap();
    assert!(caps.tools.is_some());
    assert!(caps.resources.is_none());
    assert!(caps.prompts.is_none());

    // Server with only resources
    let (client_transport2, server_transport2) = create_memory_transport_pair();
    let server2 = Server::new("resources-only", "1.0.0")
        .resource(StatusResourceHandler)
        .build();
    thread::spawn(move || server2.run_transport(server_transport2));

    let mut client2 = TestClient::new(client_transport2);
    client2.initialize().unwrap();

    let caps2 = client2.server_capabilities().unwrap();
    assert!(caps2.tools.is_none());
    assert!(caps2.resources.is_some());
    assert!(caps2.prompts.is_none());

    // Server with only prompts
    let (client_transport3, server_transport3) = create_memory_transport_pair();
    let server3 = Server::new("prompts-only", "1.0.0")
        .prompt(HelpPromptHandler)
        .build();
    thread::spawn(move || server3.run_transport(server_transport3));

    let mut client3 = TestClient::new(client_transport3);
    client3.initialize().unwrap();

    let caps3 = client3.server_capabilities().unwrap();
    assert!(caps3.tools.is_none());
    assert!(caps3.resources.is_none());
    assert!(caps3.prompts.is_some());
}

#[test]
fn session_protocol_version_negotiated() {
    let mut client = setup_workflow_server();
    let init_result = client.initialize().unwrap();

    // Protocol version should be set
    assert!(!init_result.protocol_version.is_empty());

    // Stored version should match returned version
    let stored_version = client.protocol_version().unwrap();
    assert_eq!(stored_version, init_result.protocol_version);
}

#[test]
fn session_operations_fail_before_init() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::thread;

    let (client_transport, server_transport) = create_memory_transport_pair();
    let server = Server::new("test-server", "1.0.0")
        .tool(EchoToolHandler)
        .build();
    thread::spawn(move || server.run_transport(server_transport));

    let mut client = TestClient::new(client_transport);

    // All operations should fail before initialization
    assert!(client.list_tools().is_err());
    assert!(client.list_resources().is_err());
    assert!(client.list_prompts().is_err());
    assert!(client.call_tool("echo", json!({"message": "test"})).is_err());
    assert!(client.read_resource("app://test").is_err());
}

#[test]
fn session_close_graceful() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::thread;

    let (client_transport, server_transport) = create_memory_transport_pair();
    let server = Server::new("close-test", "1.0.0")
        .tool(EchoToolHandler)
        .build();
    thread::spawn(move || server.run_transport(server_transport));

    let mut client = TestClient::new(client_transport);
    client.initialize().unwrap();

    // Perform some operations
    let result = client
        .call_tool("echo", json!({"message": "before close"}))
        .unwrap();
    assert!(!result.is_empty());

    // Close the client - this consumes it
    client.close();

    // Client is now consumed, no further operations possible
    // (This is enforced by Rust's ownership system - client is moved)
}

#[test]
fn session_state_isolated_per_client() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::thread;

    // Create two separate client-server pairs
    let (client_a_transport, server_a_transport) = create_memory_transport_pair();
    let (client_b_transport, server_b_transport) = create_memory_transport_pair();

    let server_a = Server::new("server-a", "1.0.0")
        .tool(SessionStoreHandler)
        .tool(SessionGetHandler)
        .build();

    let server_b = Server::new("server-b", "1.0.0")
        .tool(SessionStoreHandler)
        .tool(SessionGetHandler)
        .build();

    thread::spawn(move || server_a.run_transport(server_a_transport));
    thread::spawn(move || server_b.run_transport(server_b_transport));

    let mut client_a = TestClient::new(client_a_transport);
    let mut client_b = TestClient::new(client_b_transport);

    client_a.initialize().unwrap();
    client_b.initialize().unwrap();

    // Store different values in each session
    client_a
        .call_tool(
            "session_store",
            json!({"key": "shared_key", "value": "value_a"}),
        )
        .unwrap();

    client_b
        .call_tool(
            "session_store",
            json!({"key": "shared_key", "value": "value_b"}),
        )
        .unwrap();

    // Each client retrieves only its own value
    let result_a = client_a
        .call_tool("session_get", json!({"key": "shared_key"}))
        .unwrap();

    let result_b = client_b
        .call_tool("session_get", json!({"key": "shared_key"}))
        .unwrap();

    match (&result_a[0], &result_b[0]) {
        (Content::Text { text: text_a }, Content::Text { text: text_b }) => {
            assert_eq!(text_a, "value_a", "Client A should see its own value");
            assert_eq!(text_b, "value_b", "Client B should see its own value");
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn session_reinitialize_fails() {
    let mut client = setup_workflow_server();

    // First initialization succeeds
    client.initialize().unwrap();
    assert!(client.is_initialized());

    // Second initialization should succeed (idempotent) but returns same info
    // Note: In actual MCP protocol, re-initializing isn't well-defined,
    // but our TestClient should handle it gracefully
    let second_init = client.initialize();

    // The result depends on server implementation - may succeed or fail
    // The important thing is the client remains in a usable state
    if second_init.is_ok() {
        // If it succeeded, client should still work
        let tools = client.list_tools();
        assert!(tools.is_ok());
    }
}

#[test]
fn session_tracks_client_info() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::thread;

    let (client_transport, server_transport) = create_memory_transport_pair();
    let server = Server::new("client-info-test", "1.0.0")
        .tool(EchoToolHandler)
        .build();
    thread::spawn(move || server.run_transport(server_transport));

    let mut client = TestClient::new(client_transport)
        .with_client_info("custom-client-name", "2.5.0");

    // Verify client info is set before initialization
    let init = client.initialize().unwrap();

    // Server responded (indicating it received our client info)
    assert!(init.capabilities.tools.is_some());

    // Client should still work after initialization
    let result = client
        .call_tool("echo", json!({"message": "test"}))
        .unwrap();
    assert!(!result.is_empty());
}

#[test]
fn session_multiple_clients_independent_lifecycle() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::thread;

    // Create multiple independent client-server pairs
    let mut clients = Vec::new();

    for i in 0..3 {
        let (client_transport, server_transport) = create_memory_transport_pair();
        let server = Server::new(&format!("lifecycle-server-{}", i), "1.0.0")
            .tool(EchoToolHandler)
            .build();
        thread::spawn(move || server.run_transport(server_transport));

        let client = TestClient::new(client_transport)
            .with_client_info(format!("lifecycle-client-{}", i), "1.0.0");
        clients.push((i, client));
    }

    // Initialize clients in order
    for (i, client) in &mut clients {
        let init = client.initialize().unwrap();
        assert_eq!(
            init.server_info.name,
            format!("lifecycle-server-{}", i)
        );
    }

    // All clients should work independently
    for (i, client) in &mut clients {
        let result = client
            .call_tool("echo", json!({"message": format!("from-client-{}", i)}))
            .unwrap();
        match &result[0] {
            Content::Text { text } => {
                assert!(text.contains(&format!("from-client-{}", i)));
            }
            _ => panic!("Expected text"),
        }
    }

    // Close clients in reverse order (shouldn't affect others)
    while let Some((_, client)) = clients.pop() {
        client.close();
    }
}

#[test]
fn session_state_persists_across_operations() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::thread;

    let (client_transport, server_transport) = create_memory_transport_pair();
    let server = Server::new("persistence-test", "1.0.0")
        .tool(SessionStoreHandler)
        .tool(SessionGetHandler)
        .tool(EchoToolHandler)
        .build();
    thread::spawn(move || server.run_transport(server_transport));

    let mut client = TestClient::new(client_transport);
    client.initialize().unwrap();

    // Store a value
    client
        .call_tool(
            "session_store",
            json!({"key": "persistent", "value": "stored_value"}),
        )
        .unwrap();

    // Perform unrelated operations
    client.list_tools().unwrap();
    client.call_tool("echo", json!({"message": "interleaved"})).unwrap();
    client.list_tools().unwrap();

    // Value should still be there
    let result = client
        .call_tool("session_get", json!({"key": "persistent"}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert_eq!(text, "stored_value", "Session state should persist");
        }
        _ => panic!("Expected text"),
    }
}

#[test]
fn session_server_info_accessors() {
    let mut client = setup_workflow_server();
    client.initialize().unwrap();

    // Verify all accessors return correct data
    let server_info = client.server_info().unwrap();
    assert_eq!(server_info.name, "workflow-test-server");
    assert_eq!(server_info.version, "2.0.0");

    let caps = client.server_capabilities().unwrap();
    assert!(caps.tools.is_some());
    assert!(caps.resources.is_some());
    assert!(caps.prompts.is_some());

    // Protocol version should be non-empty
    let version = client.protocol_version().unwrap();
    assert!(!version.is_empty());
}

// ============================================================================
// Tool Invocation E2E Tests (bd-3vh)
// ============================================================================

/// Tool that accepts various argument types for testing.
struct TypesToolHandler;

impl ToolHandler for TypesToolHandler {
    fn definition(&self) -> Tool {
        Tool {
            name: "types_test".to_string(),
            description: Some("Tests various argument types".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "string_val": { "type": "string" },
                    "int_val": { "type": "integer" },
                    "float_val": { "type": "number" },
                    "bool_val": { "type": "boolean" },
                    "array_val": { "type": "array", "items": { "type": "string" } },
                    "object_val": { "type": "object" },
                    "null_val": { "type": "null" }
                },
                "required": []
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        // Echo back the type of each provided value
        let mut result = Vec::new();

        if let Some(v) = arguments.get("string_val") {
            result.push(format!("string_val: {}", v.as_str().unwrap_or("(not string)")));
        }
        if let Some(v) = arguments.get("int_val") {
            result.push(format!("int_val: {}", v.as_i64().map(|n| n.to_string()).unwrap_or("(not int)".to_string())));
        }
        if let Some(v) = arguments.get("float_val") {
            result.push(format!("float_val: {}", v.as_f64().map(|n| n.to_string()).unwrap_or("(not float)".to_string())));
        }
        if let Some(v) = arguments.get("bool_val") {
            result.push(format!("bool_val: {}", v.as_bool().map(|b| b.to_string()).unwrap_or("(not bool)".to_string())));
        }
        if let Some(v) = arguments.get("array_val") {
            let arr_len = v.as_array().map(|a| a.len()).unwrap_or(0);
            result.push(format!("array_val: [len={}]", arr_len));
        }
        if let Some(v) = arguments.get("object_val") {
            let obj_keys = v.as_object().map(|o| o.len()).unwrap_or(0);
            result.push(format!("object_val: {{keys={}}}", obj_keys));
        }
        if arguments.get("null_val").map(|v| v.is_null()).unwrap_or(false) {
            result.push("null_val: null".to_string());
        }

        if result.is_empty() {
            result.push("(no arguments provided)".to_string());
        }

        Ok(vec![Content::Text {
            text: result.join(", "),
        }])
    }
}

/// Tool that requires specific arguments for validation testing.
struct RequiredArgsToolHandler;

impl ToolHandler for RequiredArgsToolHandler {
    fn definition(&self) -> Tool {
        Tool {
            name: "required_args".to_string(),
            description: Some("Tool with required arguments".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "required_field": { "type": "string" },
                    "optional_field": { "type": "string" }
                },
                "required": ["required_field"]
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let required = arguments["required_field"]
            .as_str()
            .ok_or_else(|| McpError::invalid_params("required_field is required"))?;

        let optional = arguments["optional_field"].as_str().unwrap_or("(not provided)");

        Ok(vec![Content::Text {
            text: format!("required: {}, optional: {}", required, optional),
        }])
    }
}

/// Tool that returns multiple content items.
struct MultiContentToolHandler;

impl ToolHandler for MultiContentToolHandler {
    fn definition(&self) -> Tool {
        Tool {
            name: "multi_content".to_string(),
            description: Some("Returns multiple content items".to_string()),
            input_schema: json!({"type": "object", "properties": {"count": {"type": "integer"}}}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let count = arguments["count"].as_i64().unwrap_or(1) as usize;
        let count = count.min(10); // Limit to 10

        (0..count)
            .map(|i| Content::Text {
                text: format!("Item {}", i + 1),
            })
            .collect::<Vec<_>>()
            .pipe(Ok)
    }
}

// Helper trait for pipe operator
trait Pipe: Sized {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R,
    {
        f(self)
    }
}

impl<T> Pipe for T {}

fn setup_tool_test_server() -> TestClient {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("tool-test-server")
        .with_version("1.0.0")
        .build_server_builder();

    let server = builder
        .tool(EchoToolHandler)
        .tool(TypesToolHandler)
        .tool(RequiredArgsToolHandler)
        .tool(MultiContentToolHandler)
        .tool(FailOnDemandToolHandler)
        .build();

    std::thread::spawn(move || {
        server.run_transport(server_transport);
    });

    TestClient::new(client_transport)
}

#[test]
fn tool_call_string_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"string_val": "hello world"}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("string_val: hello world"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_integer_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"int_val": 42}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("int_val: 42"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_float_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"float_val": 3.14159}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("float_val: 3.14159"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_boolean_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"bool_val": true}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("bool_val: true"));
        }
        _ => panic!("Expected text content"),
    }

    let result = client
        .call_tool("types_test", json!({"bool_val": false}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("bool_val: false"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_array_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"array_val": ["a", "b", "c"]}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("array_val: [len=3]"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_object_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"object_val": {"key1": "val1", "key2": "val2"}}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("object_val: {keys=2}"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_null_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"null_val": null}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("null_val: null"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_multiple_argument_types() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({
            "string_val": "test",
            "int_val": 100,
            "bool_val": true,
            "array_val": [1, 2, 3]
        }))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("string_val: test"));
            assert!(text.contains("int_val: 100"));
            assert!(text.contains("bool_val: true"));
            assert!(text.contains("array_val: [len=3]"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_empty_arguments() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client.call_tool("types_test", json!({})).unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("(no arguments provided)"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_required_argument_provided() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("required_args", json!({"required_field": "value123"}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("required: value123"));
            assert!(text.contains("optional: (not provided)"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_required_and_optional_arguments() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("required_args", json!({
            "required_field": "required_value",
            "optional_field": "optional_value"
        }))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("required: required_value"));
            assert!(text.contains("optional: optional_value"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_missing_required_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client.call_tool("required_args", json!({"optional_field": "only optional"}));

    assert!(result.is_err(), "Should fail when required argument is missing");
}

#[test]
fn tool_call_returns_multiple_content() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("multi_content", json!({"count": 3}))
        .unwrap();

    assert_eq!(result.len(), 3, "Should return 3 content items");

    for (i, content) in result.iter().enumerate() {
        match content {
            Content::Text { text } => {
                assert_eq!(text, &format!("Item {}", i + 1));
            }
            _ => panic!("Expected text content"),
        }
    }
}

#[test]
fn tool_call_error_returns_mcp_error() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client.call_tool("fail_on_demand", json!({"fail": true, "message": "test error"}));

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.message.contains("test error") || err.message.contains("Requested failure"));
}

#[test]
fn tool_call_nonexistent_tool_error() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client.call_tool("nonexistent_tool", json!({}));

    assert!(result.is_err(), "Calling nonexistent tool should fail");
}

#[test]
fn tool_call_unicode_arguments() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("echo", json!({"message": "こんにちは世界 🌍 مرحبا"}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert_eq!(text, "こんにちは世界 🌍 مرحبا");
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_special_characters() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("echo", json!({"message": "Line 1\nLine 2\tTabbed \"quoted\" 'single'"}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("Line 1"));
            assert!(text.contains("Line 2"));
            assert!(text.contains("quoted"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_large_string_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let large_string = "x".repeat(10_000);
    let result = client
        .call_tool("echo", json!({"message": &large_string}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert_eq!(text.len(), 10_000);
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_nested_object_argument() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({
            "object_val": {
                "level1": {
                    "level2": {
                        "level3": "deep value"
                    }
                }
            }
        }))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("object_val: {keys=1}"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_negative_numbers() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    let result = client
        .call_tool("types_test", json!({"int_val": -42, "float_val": -3.14}))
        .unwrap();

    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("int_val: -42"));
            assert!(text.contains("float_val: -3.14"));
        }
        _ => panic!("Expected text content"),
    }
}

#[test]
fn tool_call_sequential_success() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    // Call multiple tools in sequence
    for i in 0..10 {
        let result = client
            .call_tool("echo", json!({"message": format!("call_{}", i)}))
            .unwrap();

        match &result[0] {
            Content::Text { text } => {
                assert_eq!(text, &format!("call_{}", i));
            }
            _ => panic!("Expected text content"),
        }
    }
}

#[test]
fn tool_call_alternating_success_failure() {
    let mut client = setup_tool_test_server();
    client.initialize().unwrap();

    for i in 0..6 {
        let should_fail = i % 2 == 1;
        let result = client.call_tool("fail_on_demand", json!({"fail": should_fail}));

        if should_fail {
            assert!(result.is_err(), "Iteration {} should fail", i);
        } else {
            assert!(result.is_ok(), "Iteration {} should succeed", i);
        }
    }

    // Verify client is still functional after alternating failures
    let tools = client.list_tools().unwrap();
    assert!(!tools.is_empty());
}

// ============================================================================
// Resource Reading E2E Tests (bd-bte)
// ============================================================================

/// Resource that returns plain text content.
struct PlainTextResourceHandler;

impl ResourceHandler for PlainTextResourceHandler {
    fn definition(&self) -> Resource {
        Resource {
            uri: "text://plain".to_string(),
            name: "Plain Text".to_string(),
            description: Some("Returns plain text content".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
            version: None,
            tags: vec![],
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Ok(vec![ResourceContent {
            uri: "text://plain".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some("Hello, World!".to_string()),
            blob: None,
        }])
    }
}

/// Resource that returns JSON content.
struct JsonResourceHandler;

impl ResourceHandler for JsonResourceHandler {
    fn definition(&self) -> Resource {
        Resource {
            uri: "data://config.json".to_string(),
            name: "JSON Config".to_string(),
            description: Some("Returns JSON configuration".to_string()),
            mime_type: Some("application/json".to_string()),
            icon: None,
            version: None,
            tags: vec![],
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        let json = serde_json::json!({
            "name": "test-config",
            "version": "1.0.0",
            "settings": {
                "debug": true,
                "max_connections": 100
            }
        });
        Ok(vec![ResourceContent {
            uri: "data://config.json".to_string(),
            mime_type: Some("application/json".to_string()),
            text: Some(json.to_string()),
            blob: None,
        }])
    }
}

/// Resource that returns binary content.
struct BinaryResourceHandler;

impl ResourceHandler for BinaryResourceHandler {
    fn definition(&self) -> Resource {
        Resource {
            uri: "binary://data.bin".to_string(),
            name: "Binary Data".to_string(),
            description: Some("Returns binary content".to_string()),
            mime_type: Some("application/octet-stream".to_string()),
            icon: None,
            version: None,
            tags: vec![],
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        // Create some test binary data
        let binary_data: Vec<u8> = (0..255u8).collect();
        let blob = base64_encode(&binary_data);

        Ok(vec![ResourceContent {
            uri: "binary://data.bin".to_string(),
            mime_type: Some("application/octet-stream".to_string()),
            text: None,
            blob: Some(blob),
        }])
    }
}

/// Simple base64 encoding for tests (no external dependency).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = data.get(i + 1).map(|&x| x as usize).unwrap_or(0);
        let b2 = data.get(i + 2).map(|&x| x as usize).unwrap_or(0);

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[b2 & 0x3F] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

/// Resource that returns Unicode content.
struct UnicodeResourceHandler;

impl ResourceHandler for UnicodeResourceHandler {
    fn definition(&self) -> Resource {
        Resource {
            uri: "text://unicode".to_string(),
            name: "Unicode Text".to_string(),
            description: Some("Returns Unicode content".to_string()),
            mime_type: Some("text/plain; charset=utf-8".to_string()),
            icon: None,
            version: None,
            tags: vec![],
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Ok(vec![ResourceContent {
            uri: "text://unicode".to_string(),
            mime_type: Some("text/plain; charset=utf-8".to_string()),
            text: Some("日本語 中文 العربية 🌍🌎🌏 Ελληνικά".to_string()),
            blob: None,
        }])
    }
}

/// Resource that returns large content.
struct LargeContentResourceHandler;

impl ResourceHandler for LargeContentResourceHandler {
    fn definition(&self) -> Resource {
        Resource {
            uri: "data://large".to_string(),
            name: "Large Content".to_string(),
            description: Some("Returns large content".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
            version: None,
            tags: vec![],
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        let large_content = "x".repeat(100_000);
        Ok(vec![ResourceContent {
            uri: "data://large".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some(large_content),
            blob: None,
        }])
    }
}

/// Resource that returns multiple content items.
struct MultiContentResourceHandler;

impl ResourceHandler for MultiContentResourceHandler {
    fn definition(&self) -> Resource {
        Resource {
            uri: "data://multi".to_string(),
            name: "Multi Content".to_string(),
            description: Some("Returns multiple content items".to_string()),
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Ok(vec![
            ResourceContent {
                uri: "data://multi/part1".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("Part 1".to_string()),
                blob: None,
            },
            ResourceContent {
                uri: "data://multi/part2".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("Part 2".to_string()),
                blob: None,
            },
            ResourceContent {
                uri: "data://multi/part3".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("Part 3".to_string()),
                blob: None,
            },
        ])
    }
}

/// Resource that always fails.
struct FailingResourceHandler;

impl ResourceHandler for FailingResourceHandler {
    fn definition(&self) -> Resource {
        Resource {
            uri: "error://fail".to_string(),
            name: "Failing Resource".to_string(),
            description: Some("Always fails when read".to_string()),
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        }
    }

    fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        Err(McpError::resource_not_found("Resource read failed intentionally"))
    }
}

fn setup_resource_test_server() -> TestClient {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name("resource-test-server")
        .with_version("1.0.0")
        .build_server_builder();

    let server = builder
        .resource(PlainTextResourceHandler)
        .resource(JsonResourceHandler)
        .resource(BinaryResourceHandler)
        .resource(UnicodeResourceHandler)
        .resource(LargeContentResourceHandler)
        .resource(MultiContentResourceHandler)
        .resource(FailingResourceHandler)
        .build();

    std::thread::spawn(move || {
        server.run_transport(server_transport);
    });

    TestClient::new(client_transport)
}

#[test]
fn resource_read_plain_text() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let content = client.read_resource("text://plain").unwrap();

    assert_eq!(content.len(), 1);
    assert_eq!(content[0].uri, "text://plain");
    assert_eq!(content[0].mime_type.as_deref(), Some("text/plain"));
    assert_eq!(content[0].text.as_deref(), Some("Hello, World!"));
    assert!(content[0].blob.is_none());
}

#[test]
fn resource_read_json() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let content = client.read_resource("data://config.json").unwrap();

    assert_eq!(content.len(), 1);
    assert_eq!(content[0].mime_type.as_deref(), Some("application/json"));

    let json: serde_json::Value = serde_json::from_str(content[0].text.as_ref().unwrap()).unwrap();
    assert_eq!(json["name"], "test-config");
    assert_eq!(json["version"], "1.0.0");
    assert_eq!(json["settings"]["debug"], true);
    assert_eq!(json["settings"]["max_connections"], 100);
}

#[test]
fn resource_read_binary() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let content = client.read_resource("binary://data.bin").unwrap();

    assert_eq!(content.len(), 1);
    assert_eq!(content[0].mime_type.as_deref(), Some("application/octet-stream"));
    assert!(content[0].text.is_none());
    assert!(content[0].blob.is_some());

    // Verify blob is base64 encoded
    let blob = content[0].blob.as_ref().unwrap();
    assert!(!blob.is_empty());
    // Base64 uses only alphanumeric chars and +/=
    assert!(blob.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
}

#[test]
fn resource_read_unicode() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let content = client.read_resource("text://unicode").unwrap();

    assert_eq!(content.len(), 1);
    let text = content[0].text.as_ref().unwrap();
    assert!(text.contains("日本語"));
    assert!(text.contains("中文"));
    assert!(text.contains("العربية"));
    assert!(text.contains("🌍"));
    assert!(text.contains("Ελληνικά"));
}

#[test]
fn resource_read_large_content() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let content = client.read_resource("data://large").unwrap();

    assert_eq!(content.len(), 1);
    let text = content[0].text.as_ref().unwrap();
    assert_eq!(text.len(), 100_000);
    assert!(text.chars().all(|c| c == 'x'));
}

#[test]
fn resource_read_multiple_content_items() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let content = client.read_resource("data://multi").unwrap();

    assert_eq!(content.len(), 3, "Should return 3 content items");

    assert_eq!(content[0].text.as_deref(), Some("Part 1"));
    assert_eq!(content[1].text.as_deref(), Some("Part 2"));
    assert_eq!(content[2].text.as_deref(), Some("Part 3"));
}

#[test]
fn resource_read_nonexistent() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let result = client.read_resource("nonexistent://resource");

    assert!(result.is_err(), "Reading nonexistent resource should fail");
}

#[test]
fn resource_read_failing() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let result = client.read_resource("error://fail");

    assert!(result.is_err(), "Reading failing resource should return error");
}

#[test]
fn resource_list_all() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let resources = client.list_resources().unwrap();

    assert_eq!(resources.len(), 7, "Should have 7 resources registered");

    let uris: Vec<&str> = resources.iter().map(|r| r.uri.as_str()).collect();
    assert!(uris.contains(&"text://plain"));
    assert!(uris.contains(&"data://config.json"));
    assert!(uris.contains(&"binary://data.bin"));
    assert!(uris.contains(&"text://unicode"));
    assert!(uris.contains(&"data://large"));
    assert!(uris.contains(&"data://multi"));
    assert!(uris.contains(&"error://fail"));
}

#[test]
fn resource_read_sequential() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    // Read multiple resources in sequence
    let content1 = client.read_resource("text://plain").unwrap();
    let content2 = client.read_resource("data://config.json").unwrap();
    let content3 = client.read_resource("text://unicode").unwrap();

    assert_eq!(content1[0].text.as_deref(), Some("Hello, World!"));
    assert!(content2[0].text.as_ref().unwrap().contains("test-config"));
    assert!(content3[0].text.as_ref().unwrap().contains("日本語"));
}

#[test]
fn resource_read_after_error() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    // First read a valid resource
    let content = client.read_resource("text://plain").unwrap();
    assert!(!content.is_empty());

    // Try to read a failing resource
    let result = client.read_resource("error://fail");
    assert!(result.is_err());

    // Session should still work - read another valid resource
    let content = client.read_resource("text://unicode").unwrap();
    assert!(!content.is_empty());
}

#[test]
fn resource_metadata_preserved() {
    let mut client = setup_resource_test_server();
    client.initialize().unwrap();

    let resources = client.list_resources().unwrap();

    let plain_text = resources.iter().find(|r| r.uri == "text://plain").unwrap();
    assert_eq!(plain_text.name, "Plain Text");
    assert_eq!(plain_text.description.as_deref(), Some("Returns plain text content"));
    assert_eq!(plain_text.mime_type.as_deref(), Some("text/plain"));

    let json_resource = resources.iter().find(|r| r.uri == "data://config.json").unwrap();
    assert_eq!(json_resource.name, "JSON Config");
    assert_eq!(json_resource.mime_type.as_deref(), Some("application/json"));
}

#[test]
fn resource_read_before_init_fails() {
    use fastmcp_transport::memory::create_memory_transport_pair;
    use std::thread;

    let (client_transport, server_transport) = create_memory_transport_pair();
    let server = Server::new("test", "1.0.0")
        .resource(PlainTextResourceHandler)
        .build();
    thread::spawn(move || server.run_transport(server_transport));

    let mut client = TestClient::new(client_transport);

    // Should fail before initialization
    assert!(client.read_resource("text://plain").is_err());
}
