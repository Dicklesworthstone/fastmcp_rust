//! Test server binary for E2E tests.
//!
//! This is a minimal MCP server used by E2E tests to verify console output.
//! It reads JSON-RPC messages from stdin and writes responses to stdout.

use std::io::{self, BufRead, Write};

use fastmcp_console::banner::StartupBanner;
use fastmcp_console::config::{BannerStyle, ConsoleConfig};
use fastmcp_console::console;
use fastmcp_console::detection::DisplayContext;
use serde::{Deserialize, Serialize};

/// JSON-RPC request.
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    params: Option<serde_json::Value>,
}

/// JSON-RPC response.
#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

/// JSON-RPC error.
#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

/// Initialize result.
#[derive(Debug, Serialize)]
struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    protocol_version: String,
    capabilities: Capabilities,
    #[serde(rename = "serverInfo")]
    server_info: ServerInfo,
}

/// Server capabilities.
#[derive(Debug, Serialize)]
struct Capabilities {
    tools: Option<ToolsCapability>,
}

/// Tools capability.
#[derive(Debug, Serialize)]
struct ToolsCapability {}

/// Server info.
#[derive(Debug, Serialize)]
struct ServerInfo {
    name: String,
    version: String,
}

/// Tool definition.
#[derive(Debug, Serialize)]
struct ToolDef {
    name: String,
    description: String,
    #[serde(rename = "inputSchema")]
    input_schema: serde_json::Value,
}

/// List tools result.
#[derive(Debug, Serialize)]
struct ListToolsResult {
    tools: Vec<ToolDef>,
}

/// Call tool result.
#[derive(Debug, Serialize)]
struct CallToolResult {
    content: Vec<Content>,
    #[serde(rename = "isError")]
    is_error: bool,
}

/// Content type.
#[derive(Debug, Serialize)]
struct Content {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

fn main() {
    // Detect context and configure console
    let context = DisplayContext::detect();
    let config = ConsoleConfig::from_env();

    // Log context detection to stderr (human-readable output)
    eprintln!("[test_server] Context: {context:?}");
    eprintln!("[test_server] Banner style: {:?}", config.banner_style);

    // Show startup banner if enabled
    if config.show_banner && !matches!(config.banner_style, BannerStyle::None) {
        render_banner(&config);
    }

    // Process JSON-RPC messages from stdin
    let stdin = io::stdin();
    let stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if l.trim().is_empty() => continue,
            Ok(l) => l,
            Err(e) => {
                eprintln!("[test_server] Read error: {e}");
                break;
            }
        };

        eprintln!("[test_server] Received: {line}");

        // Parse request
        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[test_server] Parse error: {e}");
                continue;
            }
        };

        // Handle request
        let response = handle_request(&request);

        // Write response
        let response_json = serde_json::to_string(&response).expect("serialize response");
        eprintln!("[test_server] Sending: {response_json}");

        let mut stdout = stdout.lock();
        writeln!(stdout, "{response_json}").expect("write response");
        stdout.flush().expect("flush stdout");
    }

    eprintln!("[test_server] Shutting down");
}

fn render_banner(config: &ConsoleConfig) {
    let banner = StartupBanner::new("test-server", "1.0.0")
        .tools(1)
        .resources(0)
        .prompts(0)
        .transport("stdio")
        .description("E2E test server for fastmcp-console");

    match config.banner_style {
        BannerStyle::Full => banner.render(console()),
        BannerStyle::Compact | BannerStyle::Minimal => {
            banner.no_logo().render(console());
        }
        BannerStyle::None => {}
    }
}

fn handle_request(request: &JsonRpcRequest) -> JsonRpcResponse {
    let result = match request.method.as_str() {
        "initialize" => handle_initialize(),
        "initialized" => {
            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id.clone(),
                result: Some(serde_json::Value::Null),
                error: None,
            };
        }
        "tools/list" => handle_tools_list(),
        "tools/call" => handle_tools_call(request.params.as_ref()),
        "ping" => Ok(serde_json::json!({})),
        _ => Err(JsonRpcError {
            code: -32601,
            message: format!("Method not found: {}", &request.method),
        }),
    };

    match result {
        Ok(value) => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id.clone(),
            result: Some(value),
            error: None,
        },
        Err(error) => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id.clone(),
            result: None,
            error: Some(error),
        },
    }
}

#[allow(clippy::unnecessary_wraps)]
fn handle_initialize() -> Result<serde_json::Value, JsonRpcError> {
    let result = InitializeResult {
        protocol_version: "2024-11-05".to_string(),
        capabilities: Capabilities {
            tools: Some(ToolsCapability {}),
        },
        server_info: ServerInfo {
            name: "test-server".to_string(),
            version: "1.0.0".to_string(),
        },
    };
    Ok(serde_json::to_value(result).expect("serialize"))
}

#[allow(clippy::unnecessary_wraps)]
fn handle_tools_list() -> Result<serde_json::Value, JsonRpcError> {
    let result = ListToolsResult {
        tools: vec![ToolDef {
            name: "echo".to_string(),
            description: "Echo the input message".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "message": { "type": "string" }
                },
                "required": ["message"]
            }),
        }],
    };
    Ok(serde_json::to_value(result).expect("serialize"))
}

fn handle_tools_call(
    params: Option<&serde_json::Value>,
) -> Result<serde_json::Value, JsonRpcError> {
    let params = params.ok_or_else(|| JsonRpcError {
        code: -32602,
        message: "Missing parameters".to_string(),
    })?;

    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "Missing tool name".to_string(),
        })?;

    match name {
        "echo" => {
            let message = params
                .get("arguments")
                .and_then(|a| a.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("no message");

            let result = CallToolResult {
                content: vec![Content {
                    content_type: "text".to_string(),
                    text: message.to_string(),
                }],
                is_error: false,
            };
            Ok(serde_json::to_value(result).expect("serialize"))
        }
        _ => Err(JsonRpcError {
            code: -32001,
            message: format!("Unknown tool: {name}"),
        }),
    }
}
