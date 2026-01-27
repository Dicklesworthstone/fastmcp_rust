//! JSON-RPC 2.0 message types.

use std::borrow::Cow;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// The JSON-RPC version string. Used as a static reference to avoid allocations.
pub const JSONRPC_VERSION: &str = "2.0";

/// Serializes the jsonrpc version field.
fn serialize_jsonrpc_version<S>(value: &Cow<'static, str>, serializer: S) -> Result<S::Ok, S::Error>
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

    #[test]
    fn test_request_serialization() {
        let req = JsonRpcRequest::new("tools/list", None, 1i64);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"tools/list\""));
    }

    #[test]
    fn test_notification() {
        let notif = JsonRpcRequest::notification("notifications/progress", None);
        assert!(notif.is_notification());
    }
}
