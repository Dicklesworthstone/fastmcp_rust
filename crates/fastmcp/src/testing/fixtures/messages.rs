//! JSON-RPC message templates for testing.
//!
//! Provides pre-built message fixtures for testing:
//! - Valid request/response messages
//! - Various error responses
//! - Notifications
//! - Large payloads for stress testing

use serde_json::{Value, json};

// ============================================================================
// Protocol Constants
// ============================================================================

/// Default MCP protocol version.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Default JSON-RPC version.
pub const JSONRPC_VERSION: &str = "2.0";

// ============================================================================
// Valid Request Messages
// ============================================================================

/// Creates a valid initialize request.
#[must_use]
pub fn valid_initialize_request(request_id: u64) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "roots": { "listChanged": true }
            },
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    })
}

/// Creates a valid initialized notification.
#[must_use]
pub fn valid_initialized_notification() -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "method": "notifications/initialized"
    })
}

/// Creates a valid tools/list request.
#[must_use]
pub fn valid_tools_list_request(request_id: u64) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "method": "tools/list"
    })
}

/// Creates a valid tools/call request.
#[must_use]
pub fn valid_tools_call_request(request_id: u64, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments
        }
    })
}

/// Creates a valid resources/list request.
#[must_use]
pub fn valid_resources_list_request(request_id: u64) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "method": "resources/list"
    })
}

/// Creates a valid resources/read request.
#[must_use]
pub fn valid_resources_read_request(request_id: u64, uri: &str) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "method": "resources/read",
        "params": {
            "uri": uri
        }
    })
}

/// Creates a valid prompts/list request.
#[must_use]
pub fn valid_prompts_list_request(request_id: u64) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "method": "prompts/list"
    })
}

/// Creates a valid prompts/get request.
#[must_use]
pub fn valid_prompts_get_request(request_id: u64, name: &str, arguments: Option<Value>) -> Value {
    let mut params = json!({ "name": name });
    if let Some(args) = arguments {
        params["arguments"] = args;
    }
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "method": "prompts/get",
        "params": params
    })
}

/// Creates a valid ping request.
#[must_use]
pub fn valid_ping_request(request_id: u64) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "method": "ping"
    })
}

// ============================================================================
// Valid Response Messages
// ============================================================================

/// Creates a valid success response.
#[must_use]
pub fn valid_success_response(request_id: u64, result: Value) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "result": result
    })
}

/// Creates a valid initialize response.
#[must_use]
pub fn valid_initialize_response(request_id: u64) -> Value {
    valid_success_response(
        request_id,
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "serverInfo": {
                "name": "test-server",
                "version": "1.0.0"
            },
            "capabilities": {
                "tools": { "listChanged": false },
                "resources": { "subscribe": false, "listChanged": false },
                "prompts": { "listChanged": false }
            }
        }),
    )
}

/// Creates a valid tools/list response.
#[must_use]
pub fn valid_tools_list_response(request_id: u64, tools: Vec<Value>) -> Value {
    valid_success_response(request_id, json!({ "tools": tools }))
}

/// Creates a valid tools/call response.
#[must_use]
pub fn valid_tools_call_response(request_id: u64, content: Vec<Value>, is_error: bool) -> Value {
    valid_success_response(
        request_id,
        json!({
            "content": content,
            "isError": is_error
        }),
    )
}

/// Creates a valid resources/list response.
#[must_use]
pub fn valid_resources_list_response(request_id: u64, resources: Vec<Value>) -> Value {
    valid_success_response(request_id, json!({ "resources": resources }))
}

/// Creates a valid resources/read response.
#[must_use]
pub fn valid_resources_read_response(request_id: u64, contents: Vec<Value>) -> Value {
    valid_success_response(request_id, json!({ "contents": contents }))
}

/// Creates a valid prompts/list response.
#[must_use]
pub fn valid_prompts_list_response(request_id: u64, prompts: Vec<Value>) -> Value {
    valid_success_response(request_id, json!({ "prompts": prompts }))
}

/// Creates a valid prompts/get response.
#[must_use]
pub fn valid_prompts_get_response(
    request_id: u64,
    description: Option<&str>,
    messages: Vec<Value>,
) -> Value {
    let mut result = json!({ "messages": messages });
    if let Some(desc) = description {
        result["description"] = json!(desc);
    }
    valid_success_response(request_id, result)
}

/// Creates a valid pong response.
#[must_use]
pub fn valid_pong_response(request_id: u64) -> Value {
    valid_success_response(request_id, json!({}))
}

// ============================================================================
// Error Response Messages
// ============================================================================

/// Creates an error response.
#[must_use]
pub fn error_response(request_id: u64, code: i32, message: &str, data: Option<Value>) -> Value {
    let mut error = json!({
        "code": code,
        "message": message
    });
    if let Some(d) = data {
        error["data"] = d;
    }
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": error
    })
}

/// Creates a parse error response (-32700).
#[must_use]
pub fn parse_error_response(request_id: u64) -> Value {
    error_response(request_id, -32700, "Parse error", None)
}

/// Creates an invalid request error response (-32600).
#[must_use]
pub fn invalid_request_error_response(request_id: u64) -> Value {
    error_response(request_id, -32600, "Invalid Request", None)
}

/// Creates a method not found error response (-32601).
#[must_use]
pub fn method_not_found_error_response(request_id: u64, method: &str) -> Value {
    error_response(
        request_id,
        -32601,
        &format!("Method not found: {method}"),
        None,
    )
}

/// Creates an invalid params error response (-32602).
#[must_use]
pub fn invalid_params_error_response(request_id: u64, details: &str) -> Value {
    error_response(
        request_id,
        -32602,
        "Invalid params",
        Some(json!({ "details": details })),
    )
}

/// Creates an internal error response (-32603).
#[must_use]
pub fn internal_error_response(request_id: u64, details: Option<&str>) -> Value {
    error_response(
        request_id,
        -32603,
        "Internal error",
        details.map(|d| json!({ "details": d })),
    )
}

/// Creates a resource not found error response.
#[must_use]
pub fn resource_not_found_error_response(request_id: u64, uri: &str) -> Value {
    error_response(
        request_id,
        -32002,
        &format!("Resource not found: {uri}"),
        None,
    )
}

/// Creates a tool not found error response.
#[must_use]
pub fn tool_not_found_error_response(request_id: u64, name: &str) -> Value {
    error_response(request_id, -32002, &format!("Tool not found: {name}"), None)
}

/// Creates a prompt not found error response.
#[must_use]
pub fn prompt_not_found_error_response(request_id: u64, name: &str) -> Value {
    error_response(
        request_id,
        -32002,
        &format!("Prompt not found: {name}"),
        None,
    )
}

// ============================================================================
// Invalid Messages (for error handling tests)
// ============================================================================

/// Creates various invalid JSON-RPC messages for testing error handling.
pub mod invalid {
    use serde_json::{Value, json};

    /// Missing jsonrpc field.
    #[must_use]
    pub fn missing_jsonrpc() -> Value {
        json!({
            "id": 1,
            "method": "test"
        })
    }

    /// Wrong jsonrpc version.
    #[must_use]
    pub fn wrong_jsonrpc_version() -> Value {
        json!({
            "jsonrpc": "1.0",
            "id": 1,
            "method": "test"
        })
    }

    /// Missing method field.
    #[must_use]
    pub fn missing_method() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1
        })
    }

    /// Invalid method type (not string).
    #[must_use]
    pub fn invalid_method_type() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": 123
        })
    }

    /// Invalid id type.
    #[must_use]
    pub fn invalid_id_type() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": [1, 2, 3],
            "method": "test"
        })
    }

    /// Both result and error present.
    #[must_use]
    pub fn both_result_and_error() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {},
            "error": { "code": -32600, "message": "Error" }
        })
    }

    /// Malformed JSON string.
    #[must_use]
    pub fn malformed_json_string() -> &'static str {
        r#"{"jsonrpc": "2.0", "id": 1, "method": "test""#
    }

    /// Empty object.
    #[must_use]
    pub fn empty_object() -> Value {
        json!({})
    }

    /// Null value.
    #[must_use]
    pub fn null_value() -> Value {
        Value::Null
    }

    /// Array instead of object.
    #[must_use]
    pub fn array_instead_of_object() -> Value {
        json!([1, 2, 3])
    }
}

// ============================================================================
// Notification Messages
// ============================================================================

/// Creates a notification message (no id).
#[must_use]
pub fn notification(method: &str, params: Option<Value>) -> Value {
    let mut msg = json!({
        "jsonrpc": JSONRPC_VERSION,
        "method": method
    });
    if let Some(p) = params {
        msg["params"] = p;
    }
    msg
}

/// Creates a progress notification.
#[must_use]
pub fn progress_notification(token: &str, progress: f64, message: Option<&str>) -> Value {
    notification(
        "notifications/progress",
        Some(json!({
            "progressToken": token,
            "progress": progress,
            "message": message
        })),
    )
}

/// Creates a log notification.
#[must_use]
pub fn log_notification(level: &str, data: Value) -> Value {
    notification(
        "notifications/log",
        Some(json!({
            "level": level,
            "data": data
        })),
    )
}

/// Creates a cancelled notification.
#[must_use]
pub fn cancelled_notification(request_id: u64, reason: Option<&str>) -> Value {
    notification(
        "notifications/cancelled",
        Some(json!({
            "requestId": request_id,
            "reason": reason
        })),
    )
}

// ============================================================================
// Large Payload Generators
// ============================================================================

/// Generates a large string payload of approximately the given size in KB.
#[must_use]
pub fn large_string_payload(size_kb: usize) -> String {
    let base = "abcdefghijklmnopqrstuvwxyz0123456789";
    let iterations = (size_kb * 1024) / base.len() + 1;
    base.repeat(iterations)
}

/// Generates a large JSON payload with many fields.
#[must_use]
pub fn large_json_payload(num_fields: usize) -> Value {
    let mut obj = serde_json::Map::new();
    for i in 0..num_fields {
        obj.insert(
            format!("field_{i:06}"),
            json!({
                "index": i,
                "value": format!("value_{i}"),
                "nested": {
                    "a": i * 2,
                    "b": format!("nested_{i}")
                }
            }),
        );
    }
    Value::Object(obj)
}

/// Generates a large array payload.
#[must_use]
pub fn large_array_payload(num_items: usize) -> Value {
    let items: Vec<Value> = (0..num_items)
        .map(|i| {
            json!({
                "id": i,
                "name": format!("item_{i}"),
                "data": large_string_payload(1) // 1KB per item
            })
        })
        .collect();
    Value::Array(items)
}

/// Creates a tools/call request with a large argument payload.
#[must_use]
pub fn large_tools_call_request(request_id: u64, size_kb: usize) -> Value {
    valid_tools_call_request(
        request_id,
        "large_input_tool",
        json!({
            "data": large_string_payload(size_kb)
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_initialize_request() {
        let req = valid_initialize_request(1);
        assert_eq!(req["jsonrpc"], "2.0");
        assert_eq!(req["id"], 1);
        assert_eq!(req["method"], "initialize");
        assert!(req["params"]["protocolVersion"].is_string());
    }

    #[test]
    fn test_valid_tools_call_request() {
        let req = valid_tools_call_request(2, "greeting", json!({"name": "World"}));
        assert_eq!(req["method"], "tools/call");
        assert_eq!(req["params"]["name"], "greeting");
        assert_eq!(req["params"]["arguments"]["name"], "World");
    }

    #[test]
    fn test_valid_success_response() {
        let resp = valid_success_response(1, json!({"value": 42}));
        assert_eq!(resp["id"], 1);
        assert!(resp.get("result").is_some());
        assert!(resp.get("error").is_none());
    }

    #[test]
    fn test_error_response() {
        let resp = error_response(1, -32600, "Invalid Request", None);
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["error"]["code"], -32600);
        assert!(resp.get("result").is_none());
    }

    #[test]
    fn test_parse_error_response() {
        let resp = parse_error_response(1);
        assert_eq!(resp["error"]["code"], -32700);
    }

    #[test]
    fn test_method_not_found_error() {
        let resp = method_not_found_error_response(1, "unknown_method");
        assert_eq!(resp["error"]["code"], -32601);
        assert!(
            resp["error"]["message"]
                .as_str()
                .unwrap()
                .contains("unknown_method")
        );
    }

    #[test]
    fn test_invalid_messages() {
        let missing = invalid::missing_jsonrpc();
        assert!(missing.get("jsonrpc").is_none());

        let wrong_version = invalid::wrong_jsonrpc_version();
        assert_eq!(wrong_version["jsonrpc"], "1.0");

        let missing_method = invalid::missing_method();
        assert!(missing_method.get("method").is_none());
    }

    #[test]
    fn test_notification() {
        let notif = notification("test/notification", Some(json!({"key": "value"})));
        assert!(notif.get("id").is_none());
        assert_eq!(notif["method"], "test/notification");
    }

    #[test]
    fn test_progress_notification() {
        let notif = progress_notification("token123", 0.5, Some("Halfway done"));
        assert_eq!(notif["params"]["progressToken"], "token123");
        assert_eq!(notif["params"]["progress"], 0.5);
    }

    #[test]
    fn test_large_string_payload() {
        let payload = large_string_payload(10);
        // Should be at least 10KB
        assert!(payload.len() >= 10 * 1024);
    }

    #[test]
    fn test_large_json_payload() {
        let payload = large_json_payload(100);
        let obj = payload.as_object().unwrap();
        assert_eq!(obj.len(), 100);
    }

    #[test]
    fn test_large_array_payload() {
        let payload = large_array_payload(50);
        let arr = payload.as_array().unwrap();
        assert_eq!(arr.len(), 50);
    }

    #[test]
    fn test_large_tools_call_request() {
        let req = large_tools_call_request(1, 5);
        let data = req["params"]["arguments"]["data"].as_str().unwrap();
        assert!(data.len() >= 5 * 1024);
    }

    // =========================================================================
    // Additional coverage tests (bd-3qqy)
    // =========================================================================

    #[test]
    fn valid_initialized_notification_has_no_id() {
        let notif = valid_initialized_notification();
        assert!(notif.get("id").is_none());
        assert_eq!(notif["method"], "notifications/initialized");
    }

    #[test]
    fn valid_resources_and_prompts_requests() {
        let rl = valid_resources_list_request(10);
        assert_eq!(rl["method"], "resources/list");
        assert_eq!(rl["id"], 10);

        let rr = valid_resources_read_request(11, "file:///test.txt");
        assert_eq!(rr["params"]["uri"], "file:///test.txt");

        let pl = valid_prompts_list_request(12);
        assert_eq!(pl["method"], "prompts/list");

        let pg = valid_prompts_get_request(13, "greet", Some(json!({"name": "Alice"})));
        assert_eq!(pg["params"]["name"], "greet");
        assert_eq!(pg["params"]["arguments"]["name"], "Alice");

        let pg_no_args = valid_prompts_get_request(14, "simple", None);
        assert!(pg_no_args["params"].get("arguments").is_none());
    }

    #[test]
    fn valid_ping_pong() {
        let ping = valid_ping_request(20);
        assert_eq!(ping["method"], "ping");

        let pong = valid_pong_response(20);
        assert_eq!(pong["id"], 20);
        assert!(pong["result"].is_object());
    }

    #[test]
    fn valid_initialize_response_structure() {
        let resp = valid_initialize_response(1);
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(resp["result"]["serverInfo"].is_object());
        assert!(resp["result"]["capabilities"].is_object());
    }

    #[test]
    fn valid_list_and_call_responses() {
        let tl = valid_tools_list_response(1, vec![json!({"name": "t1"})]);
        assert_eq!(tl["result"]["tools"].as_array().unwrap().len(), 1);

        let tc = valid_tools_call_response(2, vec![json!({"type": "text", "text": "hi"})], false);
        assert_eq!(tc["result"]["isError"], false);

        let tc_err = valid_tools_call_response(3, vec![], true);
        assert_eq!(tc_err["result"]["isError"], true);

        let rl = valid_resources_list_response(4, vec![]);
        assert!(rl["result"]["resources"].as_array().unwrap().is_empty());

        let rr = valid_resources_read_response(5, vec![json!({"uri": "x", "text": "data"})]);
        assert_eq!(rr["result"]["contents"].as_array().unwrap().len(), 1);

        let pl = valid_prompts_list_response(6, vec![json!({"name": "p1"})]);
        assert_eq!(pl["result"]["prompts"].as_array().unwrap().len(), 1);

        let pg = valid_prompts_get_response(7, Some("desc"), vec![]);
        assert_eq!(pg["result"]["description"], "desc");

        let pg_no_desc = valid_prompts_get_response(8, None, vec![]);
        assert!(pg_no_desc["result"].get("description").is_none());
    }

    #[test]
    fn error_response_variants() {
        let ir = invalid_request_error_response(1);
        assert_eq!(ir["error"]["code"], -32600);

        let ip = invalid_params_error_response(2, "bad param");
        assert_eq!(ip["error"]["code"], -32602);
        assert_eq!(ip["error"]["data"]["details"], "bad param");

        let ie = internal_error_response(3, Some("crash"));
        assert_eq!(ie["error"]["code"], -32603);
        assert_eq!(ie["error"]["data"]["details"], "crash");

        let ie_none = internal_error_response(4, None);
        assert!(ie_none["error"].get("data").is_none());

        let rnf = resource_not_found_error_response(5, "file:///x");
        assert!(
            rnf["error"]["message"]
                .as_str()
                .unwrap()
                .contains("file:///x")
        );

        let tnf = tool_not_found_error_response(6, "missing_tool");
        assert!(
            tnf["error"]["message"]
                .as_str()
                .unwrap()
                .contains("missing_tool")
        );

        let pnf = prompt_not_found_error_response(7, "missing_prompt");
        assert!(
            pnf["error"]["message"]
                .as_str()
                .unwrap()
                .contains("missing_prompt")
        );
    }

    #[test]
    fn invalid_message_remaining_variants() {
        let imt = invalid::invalid_method_type();
        assert_eq!(imt["method"], 123);

        let iid = invalid::invalid_id_type();
        assert!(iid["id"].is_array());

        let bre = invalid::both_result_and_error();
        assert!(bre.get("result").is_some());
        assert!(bre.get("error").is_some());

        let mjs = invalid::malformed_json_string();
        assert!(!mjs.is_empty());

        let eo = invalid::empty_object();
        assert!(eo.as_object().unwrap().is_empty());

        let nv = invalid::null_value();
        assert!(nv.is_null());

        let aio = invalid::array_instead_of_object();
        assert!(aio.is_array());
    }

    #[test]
    fn notification_without_params() {
        let notif = notification("test/event", None);
        assert!(notif.get("params").is_none());
        assert!(notif.get("id").is_none());
    }

    #[test]
    fn log_and_cancelled_notifications() {
        let log = log_notification("error", json!("something failed"));
        assert_eq!(log["method"], "notifications/log");
        assert_eq!(log["params"]["level"], "error");

        let cancel = cancelled_notification(42, Some("timeout"));
        assert_eq!(cancel["method"], "notifications/cancelled");
        assert_eq!(cancel["params"]["requestId"], 42);
        assert_eq!(cancel["params"]["reason"], "timeout");
    }

    #[test]
    fn error_response_with_data() {
        let resp = error_response(1, -32000, "Custom error", Some(json!({"extra": true})));
        assert_eq!(resp["error"]["data"]["extra"], true);
    }
}
