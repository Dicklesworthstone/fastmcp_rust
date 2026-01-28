//! Table renderers example.
//!
//! Renders tools, resources, and prompts using rich tables with plain fallback.

use fastmcp_console::console::FastMcpConsole;
use fastmcp_console::tables::{PromptTableRenderer, ResourceTableRenderer, ToolTableRenderer};
use fastmcp_protocol::{Prompt, PromptArgument, Resource, Tool};
use serde_json::json;

fn main() {
    let console = FastMcpConsole::new();

    let tools = vec![Tool {
        name: "add".to_string(),
        description: Some("Add two numbers".to_string()),
        input_schema: json!({
            "type": "object",
            "properties": {
                "a": { "type": "integer", "description": "First number" },
                "b": { "type": "integer", "description": "Second number" }
            },
            "required": ["a", "b"]
        }),
        icon: None,
    }];

    let resources = vec![Resource {
        uri: "file://config.json".to_string(),
        name: "config".to_string(),
        description: Some("Application configuration".to_string()),
        mime_type: Some("application/json".to_string()),
        icon: None,
    }];

    let prompts = vec![Prompt {
        name: "greet".to_string(),
        description: Some("Generate a greeting".to_string()),
        arguments: vec![PromptArgument {
            name: "name".to_string(),
            description: Some("Name to greet".to_string()),
            required: true,
        }],
        icon: None,
    }];

    ToolTableRenderer::detect().render(&tools, &console);
    ResourceTableRenderer::detect().render(&resources, &console);
    PromptTableRenderer::detect().render(&prompts, &console);
}
