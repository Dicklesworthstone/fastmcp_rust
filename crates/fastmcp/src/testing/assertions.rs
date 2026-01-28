//! Assertion helpers for testing JSON-RPC and MCP compliance.
//!
//! Provides convenient assertion functions for validating protocol messages.

use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, JSONRPC_VERSION};

/// Validates that a JSON-RPC message is well-formed.
///
/// Checks:
/// - `jsonrpc` field is "2.0"
/// - Request has required fields (method)
/// - Response has either result or error (not both)
///
/// # Panics
///
/// Panics if the message is malformed.
///
/// # Example
///
/// ```ignore
/// let request = JsonRpcRequest::new("test", None, 1i64);
/// assert_json_rpc_valid(&JsonRpcMessage::Request(request));
/// ```
pub fn assert_json_rpc_valid(message: &JsonRpcMessage) {
    match message {
        JsonRpcMessage::Request(req) => {
            assert_eq!(
                req.jsonrpc.as_ref(),
                JSONRPC_VERSION,
                "JSON-RPC version must be 2.0"
            );
            assert!(
                !req.method.is_empty(),
                "JSON-RPC request must have a method"
            );
        }
        JsonRpcMessage::Response(resp) => {
            assert_eq!(
                resp.jsonrpc.as_ref(),
                JSONRPC_VERSION,
                "JSON-RPC version must be 2.0"
            );
            // Response must have either result or error, not both
            let has_result = resp.result.is_some();
            let has_error = resp.error.is_some();
            assert!(
                has_result || has_error,
                "JSON-RPC response must have either result or error"
            );
            assert!(
                !(has_result && has_error),
                "JSON-RPC response cannot have both result and error"
            );
        }
    }
}

/// Validates that a JSON-RPC response indicates success.
///
/// # Panics
///
/// Panics if the response has an error.
///
/// # Example
///
/// ```ignore
/// let response = JsonRpcResponse::success(RequestId::Number(1), json!({}));
/// assert_json_rpc_success(&response);
/// ```
pub fn assert_json_rpc_success(response: &JsonRpcResponse) {
    assert!(
        response.error.is_none(),
        "Expected success response but got error: {:?}",
        response.error
    );
    assert!(
        response.result.is_some(),
        "Success response must have a result"
    );
}

/// Validates that a JSON-RPC response indicates an error.
///
/// # Arguments
///
/// * `response` - The response to validate
/// * `expected_code` - Optional expected error code
///
/// # Panics
///
/// Panics if the response is successful or has wrong error code.
///
/// # Example
///
/// ```ignore
/// let response = JsonRpcResponse::error(
///     Some(RequestId::Number(1)),
///     McpError::method_not_found("unknown").into(),
/// );
/// assert_json_rpc_error(&response, Some(-32601));
/// ```
pub fn assert_json_rpc_error(response: &JsonRpcResponse, expected_code: Option<i32>) {
    assert!(
        response.error.is_some(),
        "Expected error response but got success"
    );
    assert!(
        response.result.is_none(),
        "Error response should not have a result"
    );

    if let Some(expected) = expected_code {
        let actual = response.error.as_ref().unwrap().code;
        assert_eq!(
            actual, expected,
            "Expected error code {expected} but got {actual}"
        );
    }
}

/// Validates that an MCP response is compliant with the protocol.
///
/// Checks JSON-RPC validity plus MCP-specific constraints:
/// - Successful initialize response has required fields
/// - Tool list response has tools array
/// - Resource list response has resources array
/// - etc.
///
/// # Arguments
///
/// * `method` - The MCP method that was called
/// * `response` - The response to validate
///
/// # Panics
///
/// Panics if the response is not MCP-compliant.
///
/// # Example
///
/// ```ignore
/// let response = JsonRpcResponse::success(
///     RequestId::Number(1),
///     json!({"tools": []}),
/// );
/// assert_mcp_compliant("tools/list", &response);
/// ```
pub fn assert_mcp_compliant(method: &str, response: &JsonRpcResponse) {
    // First validate JSON-RPC structure
    assert_json_rpc_valid(&JsonRpcMessage::Response(response.clone()));

    // If it's an error, no further MCP validation needed
    if response.error.is_some() {
        return;
    }

    let result = response.result.as_ref().expect("Response must have result");

    // Method-specific validation
    match method {
        "initialize" => {
            assert!(
                result.get("protocolVersion").is_some(),
                "Initialize response must have protocolVersion"
            );
            assert!(
                result.get("capabilities").is_some(),
                "Initialize response must have capabilities"
            );
            assert!(
                result.get("serverInfo").is_some(),
                "Initialize response must have serverInfo"
            );
        }
        "tools/list" => {
            assert!(
                result.get("tools").is_some(),
                "tools/list response must have tools array"
            );
            assert!(
                result["tools"].is_array(),
                "tools must be an array"
            );
        }
        "tools/call" => {
            assert!(
                result.get("content").is_some(),
                "tools/call response must have content"
            );
            assert!(
                result["content"].is_array(),
                "content must be an array"
            );
        }
        "resources/list" => {
            assert!(
                result.get("resources").is_some(),
                "resources/list response must have resources array"
            );
            assert!(
                result["resources"].is_array(),
                "resources must be an array"
            );
        }
        "resources/read" => {
            assert!(
                result.get("contents").is_some(),
                "resources/read response must have contents"
            );
            assert!(
                result["contents"].is_array(),
                "contents must be an array"
            );
        }
        "resources/templates/list" => {
            assert!(
                result.get("resourceTemplates").is_some(),
                "resources/templates/list response must have resourceTemplates"
            );
            assert!(
                result["resourceTemplates"].is_array(),
                "resourceTemplates must be an array"
            );
        }
        "prompts/list" => {
            assert!(
                result.get("prompts").is_some(),
                "prompts/list response must have prompts array"
            );
            assert!(
                result["prompts"].is_array(),
                "prompts must be an array"
            );
        }
        "prompts/get" => {
            assert!(
                result.get("messages").is_some(),
                "prompts/get response must have messages"
            );
            assert!(
                result["messages"].is_array(),
                "messages must be an array"
            );
        }
        _ => {
            // Unknown method - just verify it's valid JSON
        }
    }
}

/// Validates that a tool definition is MCP-compliant.
///
/// # Panics
///
/// Panics if the tool is malformed.
pub fn assert_tool_valid(tool: &serde_json::Value) {
    assert!(
        tool.get("name").is_some(),
        "Tool must have a name"
    );
    assert!(
        tool["name"].is_string(),
        "Tool name must be a string"
    );
    // inputSchema is optional but if present must be an object
    if let Some(schema) = tool.get("inputSchema") {
        assert!(
            schema.is_object(),
            "inputSchema must be an object"
        );
    }
}

/// Validates that a resource definition is MCP-compliant.
///
/// # Panics
///
/// Panics if the resource is malformed.
pub fn assert_resource_valid(resource: &serde_json::Value) {
    assert!(
        resource.get("uri").is_some(),
        "Resource must have a uri"
    );
    assert!(
        resource["uri"].is_string(),
        "Resource uri must be a string"
    );
    assert!(
        resource.get("name").is_some(),
        "Resource must have a name"
    );
    assert!(
        resource["name"].is_string(),
        "Resource name must be a string"
    );
}

/// Validates that a prompt definition is MCP-compliant.
///
/// # Panics
///
/// Panics if the prompt is malformed.
pub fn assert_prompt_valid(prompt: &serde_json::Value) {
    assert!(
        prompt.get("name").is_some(),
        "Prompt must have a name"
    );
    assert!(
        prompt["name"].is_string(),
        "Prompt name must be a string"
    );
}

/// Validates that content is MCP-compliant.
///
/// # Panics
///
/// Panics if the content is malformed.
pub fn assert_content_valid(content: &serde_json::Value) {
    assert!(
        content.get("type").is_some(),
        "Content must have a type"
    );
    let content_type = content["type"].as_str().expect("type must be a string");
    match content_type {
        "text" => {
            assert!(
                content.get("text").is_some(),
                "Text content must have text field"
            );
        }
        "image" => {
            assert!(
                content.get("data").is_some(),
                "Image content must have data field"
            );
            assert!(
                content.get("mimeType").is_some(),
                "Image content must have mimeType field"
            );
        }
        "audio" => {
            assert!(
                content.get("data").is_some(),
                "Audio content must have data field"
            );
            assert!(
                content.get("mimeType").is_some(),
                "Audio content must have mimeType field"
            );
        }
        "resource" => {
            assert!(
                content.get("resource").is_some(),
                "Resource content must have resource field"
            );
        }
        _ => {
            // Unknown content type - allow for extensibility
        }
    }
}

/// Validates that a JSON-RPC request is a valid notification.
///
/// A notification has no `id` field.
///
/// # Panics
///
/// Panics if the request is not a notification.
pub fn assert_is_notification(request: &JsonRpcRequest) {
    assert!(
        request.id.is_none(),
        "Notification must not have an id field"
    );
}

/// Validates that a JSON-RPC request is a valid request (not notification).
///
/// A request has an `id` field.
///
/// # Panics
///
/// Panics if the request is a notification.
pub fn assert_is_request(request: &JsonRpcRequest) {
    assert!(
        request.id.is_some(),
        "Request must have an id field"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::RequestId;

    #[test]
    fn test_valid_request() {
        let request = JsonRpcRequest::new("test/method", None, 1i64);
        assert_json_rpc_valid(&JsonRpcMessage::Request(request));
    }

    #[test]
    fn test_valid_success_response() {
        let response = JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({}));
        assert_json_rpc_valid(&JsonRpcMessage::Response(response.clone()));
        assert_json_rpc_success(&response);
    }

    #[test]
    fn test_valid_error_response() {
        let error = fastmcp_protocol::JsonRpcError {
            code: -32601,
            message: "Method not found".to_string(),
            data: None,
        };
        let response = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Borrowed(JSONRPC_VERSION),
            id: Some(RequestId::Number(1)),
            result: None,
            error: Some(error),
        };
        assert_json_rpc_valid(&JsonRpcMessage::Response(response.clone()));
        assert_json_rpc_error(&response, Some(-32601));
    }

    #[test]
    fn test_mcp_compliant_tools_list() {
        let response = JsonRpcResponse::success(
            RequestId::Number(1),
            serde_json::json!({
                "tools": []
            }),
        );
        assert_mcp_compliant("tools/list", &response);
    }

    #[test]
    fn test_mcp_compliant_initialize() {
        let response = JsonRpcResponse::success(
            RequestId::Number(1),
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {
                    "name": "test",
                    "version": "1.0"
                }
            }),
        );
        assert_mcp_compliant("initialize", &response);
    }

    #[test]
    fn test_valid_tool() {
        let tool = serde_json::json!({
            "name": "my_tool",
            "description": "A test tool",
            "inputSchema": {
                "type": "object"
            }
        });
        assert_tool_valid(&tool);
    }

    #[test]
    fn test_valid_resource() {
        let resource = serde_json::json!({
            "uri": "file:///test.txt",
            "name": "Test File"
        });
        assert_resource_valid(&resource);
    }

    #[test]
    fn test_valid_prompt() {
        let prompt = serde_json::json!({
            "name": "greeting",
            "description": "A greeting prompt"
        });
        assert_prompt_valid(&prompt);
    }

    #[test]
    fn test_valid_text_content() {
        let content = serde_json::json!({
            "type": "text",
            "text": "Hello, world!"
        });
        assert_content_valid(&content);
    }

    #[test]
    fn test_is_notification() {
        let notification = JsonRpcRequest::notification("test", None);
        assert_is_notification(&notification);
    }

    #[test]
    fn test_is_request() {
        let request = JsonRpcRequest::new("test", None, 1i64);
        assert_is_request(&request);
    }
}
