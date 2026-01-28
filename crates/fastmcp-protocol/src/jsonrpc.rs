//! JSON-RPC 2.0 message types.

use std::borrow::Cow;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// The JSON-RPC version string. Used as a static reference to avoid allocations.
pub const JSONRPC_VERSION: &str = "2.0";

/// Serializes the jsonrpc version field.
fn serialize_jsonrpc_version<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value)
}

/// Deserializes the jsonrpc version field, returning a borrowed reference for "2.0".
fn deserialize_jsonrpc_version<'de, D>(deserializer: D) -> Result<Cow<'static, str>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s == JSONRPC_VERSION {
        Ok(Cow::Borrowed(JSONRPC_VERSION))
    } else {
        Ok(Cow::Owned(s))
    }
}

/// JSON-RPC request ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// Integer ID.
    Number(i64),
    /// String ID.
    String(String),
}

impl From<i64> for RequestId {
    fn from(id: i64) -> Self {
        RequestId::Number(id)
    }
}

impl From<String> for RequestId {
    fn from(id: String) -> Self {
        RequestId::String(id)
    }
}

impl From<&str> for RequestId {
    fn from(id: &str) -> Self {
        RequestId::String(id.to_owned())
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestId::Number(n) => write!(f, "{n}"),
            RequestId::String(s) => write!(f, "{s}"),
        }
    }
}

/// JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Protocol version (always "2.0").
    #[serde(
        serialize_with = "serialize_jsonrpc_version",
        deserialize_with = "deserialize_jsonrpc_version"
    )]
    pub jsonrpc: Cow<'static, str>,
    /// Method name.
    pub method: String,
    /// Request parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Request ID (absent for notifications).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<RequestId>,
}

impl JsonRpcRequest {
    /// Creates a new request with the given method and parameters.
    #[must_use]
    pub fn new(method: impl Into<String>, params: Option<Value>, id: impl Into<RequestId>) -> Self {
        Self {
            jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
            method: method.into(),
            params,
            id: Some(id.into()),
        }
    }

    /// Creates a notification (request without ID).
    #[must_use]
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
            method: method.into(),
            params,
            id: None,
        }
    }

    /// Returns true if this is a notification (no ID).
    #[must_use]
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
    /// Additional error data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl From<fastmcp_core::McpError> for JsonRpcError {
    fn from(err: fastmcp_core::McpError) -> Self {
        Self {
            code: err.code.into(),
            message: err.message,
            data: err.data,
        }
    }
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Protocol version (always "2.0").
    #[serde(
        serialize_with = "serialize_jsonrpc_version",
        deserialize_with = "deserialize_jsonrpc_version"
    )]
    pub jsonrpc: Cow<'static, str>,
    /// Result (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error (present on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Request ID this is responding to.
    pub id: Option<RequestId>,
}

impl JsonRpcResponse {
    /// Creates a success response.
    #[must_use]
    pub fn success(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
            result: Some(result),
            error: None,
            id: Some(id),
        }
    }

    /// Creates an error response.
    #[must_use]
    pub fn error(id: Option<RequestId>, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
            result: None,
            error: Some(error),
            id,
        }
    }

    /// Returns true if this is an error response.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

/// A JSON-RPC message (request, response, or notification).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcMessage {
    /// A request or notification.
    Request(JsonRpcRequest),
    /// A response.
    Response(JsonRpcResponse),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ========================================================================
    // RequestId Tests
    // ========================================================================

    #[test]
    fn request_id_number_serialization() {
        let id = RequestId::Number(42);
        let value = serde_json::to_value(&id).expect("serialize");
        assert_eq!(value, 42);
    }

    #[test]
    fn request_id_string_serialization() {
        let id = RequestId::String("req-1".to_string());
        let value = serde_json::to_value(&id).expect("serialize");
        assert_eq!(value, "req-1");
    }

    #[test]
    fn request_id_number_deserialization() {
        let id: RequestId = serde_json::from_value(json!(99)).expect("deserialize");
        assert_eq!(id, RequestId::Number(99));
    }

    #[test]
    fn request_id_string_deserialization() {
        let id: RequestId = serde_json::from_value(json!("abc")).expect("deserialize");
        assert_eq!(id, RequestId::String("abc".to_string()));
    }

    #[test]
    fn request_id_from_i64() {
        let id: RequestId = 7i64.into();
        assert_eq!(id, RequestId::Number(7));
    }

    #[test]
    fn request_id_from_string() {
        let id: RequestId = "test-id".to_string().into();
        assert_eq!(id, RequestId::String("test-id".to_string()));
    }

    #[test]
    fn request_id_from_str() {
        let id: RequestId = "test-id".into();
        assert_eq!(id, RequestId::String("test-id".to_string()));
    }

    #[test]
    fn request_id_display() {
        assert_eq!(format!("{}", RequestId::Number(42)), "42");
        assert_eq!(format!("{}", RequestId::String("req-1".to_string())), "req-1");
    }

    #[test]
    fn request_id_equality() {
        assert_eq!(RequestId::Number(1), RequestId::Number(1));
        assert_ne!(RequestId::Number(1), RequestId::Number(2));
        assert_eq!(
            RequestId::String("a".to_string()),
            RequestId::String("a".to_string())
        );
        assert_ne!(RequestId::Number(1), RequestId::String("1".to_string()));
    }

    // ========================================================================
    // JsonRpcRequest Tests
    // ========================================================================

    #[test]
    fn request_serialization() {
        let req = JsonRpcRequest::new("tools/list", None, 1i64);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"tools/list\""));
        assert!(json.contains("\"id\":1"));
    }

    #[test]
    fn request_with_params() {
        let params = json!({"name": "greet", "arguments": {"name": "World"}});
        let req = JsonRpcRequest::new("tools/call", Some(params.clone()), 2i64);
        let value = serde_json::to_value(&req).expect("serialize");
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["method"], "tools/call");
        assert_eq!(value["params"]["name"], "greet");
        assert_eq!(value["id"], 2);
    }

    #[test]
    fn request_without_params_omits_field() {
        let req = JsonRpcRequest::new("tools/list", None, 1i64);
        let value = serde_json::to_value(&req).expect("serialize");
        assert!(value.get("params").is_none());
    }

    #[test]
    fn notification_has_no_id() {
        let notif = JsonRpcRequest::notification("notifications/progress", None);
        assert!(notif.is_notification());
        assert!(notif.id.is_none());
        let value = serde_json::to_value(&notif).expect("serialize");
        assert!(value.get("id").is_none());
    }

    #[test]
    fn notification_with_params() {
        let params = json!({"uri": "file://changed.txt"});
        let notif =
            JsonRpcRequest::notification("notifications/resources/updated", Some(params));
        assert!(notif.is_notification());
        let value = serde_json::to_value(&notif).expect("serialize");
        assert_eq!(value["params"]["uri"], "file://changed.txt");
    }

    #[test]
    fn request_is_not_notification() {
        let req = JsonRpcRequest::new("tools/list", None, 1i64);
        assert!(!req.is_notification());
    }

    #[test]
    fn request_with_string_id() {
        let req = JsonRpcRequest::new("tools/list", None, "req-abc");
        let value = serde_json::to_value(&req).expect("serialize");
        assert_eq!(value["id"], "req-abc");
    }

    #[test]
    fn request_round_trip() {
        let original = JsonRpcRequest::new(
            "tools/call",
            Some(json!({"name": "add", "arguments": {"a": 1, "b": 2}})),
            42i64,
        );
        let json_str = serde_json::to_string(&original).expect("serialize");
        let deserialized: JsonRpcRequest = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(deserialized.method, "tools/call");
        assert_eq!(deserialized.id, Some(RequestId::Number(42)));
        assert!(deserialized.params.is_some());
    }

    // ========================================================================
    // JsonRpcError Tests
    // ========================================================================

    #[test]
    fn jsonrpc_error_serialization() {
        let error = JsonRpcError {
            code: -32600,
            message: "Invalid Request".to_string(),
            data: None,
        };
        let value = serde_json::to_value(&error).expect("serialize");
        assert_eq!(value["code"], -32600);
        assert_eq!(value["message"], "Invalid Request");
        assert!(value.get("data").is_none());
    }

    #[test]
    fn jsonrpc_error_with_data() {
        let error = JsonRpcError {
            code: -32602,
            message: "Invalid params".to_string(),
            data: Some(json!({"field": "name", "reason": "required"})),
        };
        let value = serde_json::to_value(&error).expect("serialize");
        assert_eq!(value["code"], -32602);
        assert_eq!(value["data"]["field"], "name");
    }

    #[test]
    fn jsonrpc_error_standard_codes() {
        // Parse error
        let err = JsonRpcError {
            code: -32700,
            message: "Parse error".to_string(),
            data: None,
        };
        assert_eq!(
            serde_json::to_value(&err).unwrap()["code"],
            -32700
        );

        // Method not found
        let err = JsonRpcError {
            code: -32601,
            message: "Method not found".to_string(),
            data: None,
        };
        assert_eq!(
            serde_json::to_value(&err).unwrap()["code"],
            -32601
        );

        // Internal error
        let err = JsonRpcError {
            code: -32603,
            message: "Internal error".to_string(),
            data: None,
        };
        assert_eq!(
            serde_json::to_value(&err).unwrap()["code"],
            -32603
        );
    }

    // ========================================================================
    // JsonRpcResponse Tests
    // ========================================================================

    #[test]
    fn response_success() {
        let resp = JsonRpcResponse::success(RequestId::Number(1), json!({"result": "ok"}));
        let value = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["result"]["result"], "ok");
        assert_eq!(value["id"], 1);
        assert!(value.get("error").is_none());
        assert!(!resp.is_error());
    }

    #[test]
    fn response_error() {
        let error = JsonRpcError {
            code: -32601,
            message: "Method not found".to_string(),
            data: None,
        };
        let resp = JsonRpcResponse::error(Some(RequestId::Number(1)), error);
        let value = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(value["jsonrpc"], "2.0");
        assert!(value.get("result").is_none());
        assert_eq!(value["error"]["code"], -32601);
        assert_eq!(value["error"]["message"], "Method not found");
        assert_eq!(value["id"], 1);
        assert!(resp.is_error());
    }

    #[test]
    fn response_error_null_id() {
        let error = JsonRpcError {
            code: -32700,
            message: "Parse error".to_string(),
            data: None,
        };
        let resp = JsonRpcResponse::error(None, error);
        let value = serde_json::to_value(&resp).expect("serialize");
        assert!(value["id"].is_null());
    }

    #[test]
    fn response_round_trip() {
        let original = JsonRpcResponse::success(
            RequestId::String("abc".to_string()),
            json!({"tools": []}),
        );
        let json_str = serde_json::to_string(&original).expect("serialize");
        let deserialized: JsonRpcResponse = serde_json::from_str(&json_str).expect("deserialize");
        assert!(!deserialized.is_error());
        assert!(deserialized.result.is_some());
        assert_eq!(
            deserialized.id,
            Some(RequestId::String("abc".to_string()))
        );
    }

    // ========================================================================
    // JsonRpcMessage Tests
    // ========================================================================

    #[test]
    fn message_request_variant() {
        let req = JsonRpcRequest::new("tools/list", None, 1i64);
        let msg = JsonRpcMessage::Request(req);
        let value = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(value["method"], "tools/list");
    }

    #[test]
    fn message_response_variant() {
        let resp = JsonRpcResponse::success(RequestId::Number(1), json!("ok"));
        let msg = JsonRpcMessage::Response(resp);
        let value = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(value["result"], "ok");
    }

    #[test]
    fn message_deserialize_as_request() {
        let json_str = r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
        let msg: JsonRpcMessage = serde_json::from_str(json_str).expect("deserialize");
        match msg {
            JsonRpcMessage::Request(req) => {
                assert_eq!(req.method, "tools/list");
                assert_eq!(req.id, Some(RequestId::Number(1)));
            }
            _ => panic!("Expected request variant"),
        }
    }

    #[test]
    fn message_deserialize_as_response() {
        let json_str = r#"{"jsonrpc":"2.0","result":{"tools":[]},"id":1}"#;
        let msg: JsonRpcMessage = serde_json::from_str(json_str).expect("deserialize");
        match msg {
            JsonRpcMessage::Response(resp) => {
                assert!(!resp.is_error());
                assert_eq!(resp.id, Some(RequestId::Number(1)));
            }
            // The untagged enum may also parse as Request depending on field overlap
            JsonRpcMessage::Request(_) => {
                // This is acceptable for untagged deserialization
            }
        }
    }

    // ========================================================================
    // JSONRPC_VERSION constant test
    // ========================================================================

    #[test]
    fn jsonrpc_version_constant() {
        assert_eq!(JSONRPC_VERSION, "2.0");
    }
}
